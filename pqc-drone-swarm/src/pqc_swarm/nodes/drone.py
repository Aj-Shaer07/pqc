"""Autonomous Drone Node with decentralized threshold verification, anti-replay, and execution."""

import json
import secrets
import time
from typing import Dict, List, Optional, Set, Tuple, Any
from pqc_swarm.crypto.falcon import FalconSigner
from pqc_swarm.crypto.sss import reconstruct_secret
from pqc_swarm.crypto.aead import encrypt_payload, decrypt_payload
from pqc_swarm.crypto.anti_replay import AntiReplayFilter
from pqc_swarm.models.messages import CommandMessage, ApprovalMessage, ShareMessage
from pqc_swarm.models.registry import TrustRegistry


class DroneNode:
    """
    Decentralized Autonomous Drone.
    Holds its own keypair, Shamir share, trust registry, anti-replay filter, and optional mesh_key.
    Independently verifies GS commands, checks peer approvals, profiles performance metrics,
    decrypts broadcast-encrypted shares, and executes payload upon reaching threshold.
    """

    def __init__(
        self,
        drone_id: str,
        share: Tuple[int, int],
        threshold: int,
        trust_registry: TrustRegistry,
        signer: Optional[FalconSigner] = None,
        anti_replay: Optional[AntiReplayFilter] = None,
        freshness_window_sec: float = 5.0,
        mesh_key: Optional[bytes] = None,
    ):
        self.drone_id = drone_id
        self.share = share  # (x, y)
        self.threshold = threshold
        self.trust_registry = trust_registry
        self.signer = signer or FalconSigner(512)
        self.anti_replay = anti_replay or AntiReplayFilter(window_seconds=freshness_window_sec)
        self.mesh_key = mesh_key

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

        # Detailed performance metrics per command_id
        self.command_metrics: Dict[str, Dict[str, Any]] = {}
        self.last_rejection_reason: Optional[str] = None

    def verify_gs_command(
        self,
        command: CommandMessage,
        current_time: Optional[float] = None,
    ) -> Tuple[bool, float]:
        """
        Verify the Ground Station signature on an incoming command with anti-replay checks.
        Returns (is_valid, elapsed_seconds).
        """
        start = time.perf_counter()

        # 1. Anti-Replay and Freshness verification
        cmd_identifier = f"CMD:{command.command_id}:{command.nonce_hex}"
        is_fresh, reason = self.anti_replay.check_freshness(
            cmd_identifier, command.timestamp, current_time=current_time
        )
        if not is_fresh:
            self.last_rejection_reason = reason
            elapsed = time.perf_counter() - start
            return False, elapsed

        # 2. Check Ground Station Public Key
        if not self.trust_registry.gs_public_key:
            self.last_rejection_reason = "No GS public key in trust registry"
            elapsed = time.perf_counter() - start
            return False, elapsed

        gs_pk = self.trust_registry.gs_public_key
        sig_bytes = bytes.fromhex(command.gs_signature_hex)

        # 3. Falcon-512 Signature verification
        is_valid = self.signer.verify(gs_pk, command.digest(), sig_bytes)
        elapsed = time.perf_counter() - start

        if is_valid:
            self.anti_replay.record_seen(cmd_identifier, command.timestamp, current_time=current_time)
            self.last_rejection_reason = None
            self.known_commands[command.command_id] = command
            if command.command_id not in self.peer_approvals:
                self.peer_approvals[command.command_id] = set()
            if command.command_id not in self.collected_shares:
                self.collected_shares[command.command_id] = []

            # Initialize command performance metrics
            self.command_metrics[command.command_id] = {
                "command_id": command.command_id,
                "drone_id": self.drone_id,
                "command_timestamp": command.timestamp,
                "received_timestamp": time.time(),
                "gs_verify_time_ms": round(elapsed * 1000, 3),
                "approval_create_time_ms": 0.0,
                "peer_verify_times_ms": [],
                "reconstruct_time_ms": 0.0,
                "decrypt_time_ms": 0.0,
                "total_consensus_time_ms": 0.0,
            }
        else:
            self.last_rejection_reason = "Invalid Falcon-512 GS signature"

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

        if command_id in self.command_metrics:
            self.command_metrics[command_id]["approval_create_time_ms"] = round(elapsed * 1000, 3)

        return signed_app, elapsed

    def process_peer_approval(
        self,
        approval: ApprovalMessage,
        current_time: Optional[float] = None,
    ) -> Tuple[bool, float]:
        """
        Decentralized verification of peer drone approvals with anti-replay checks.
        Ensures freshness, sender trust, and Falcon signature validity.
        """
        start = time.perf_counter()

        # 1. Anti-Replay and Freshness verification
        app_identifier = f"APP:{approval.command_id}:{approval.drone_id}"
        is_fresh, reason = self.anti_replay.check_freshness(
            app_identifier, approval.timestamp, current_time=current_time
        )
        if not is_fresh:
            self.last_rejection_reason = reason
            elapsed = time.perf_counter() - start
            return False, elapsed

        # 2. Check Trust Registry
        if not self.trust_registry.is_trusted(approval.drone_id):
            self.last_rejection_reason = f"Untrusted drone: {approval.drone_id}"
            elapsed = time.perf_counter() - start
            return False, elapsed

        peer_pk = self.trust_registry.get_public_key(approval.drone_id)
        if not peer_pk:
            self.last_rejection_reason = f"Missing public key for drone: {approval.drone_id}"
            elapsed = time.perf_counter() - start
            return False, elapsed

        # 3. Falcon-512 Signature verification
        sig_bytes = bytes.fromhex(approval.signature_hex)
        is_valid = self.signer.verify(peer_pk, approval.digest(), sig_bytes)
        elapsed = time.perf_counter() - start

        if is_valid:
            self.anti_replay.record_seen(app_identifier, approval.timestamp, current_time=current_time)
            self.last_rejection_reason = None
            self.peer_approvals.setdefault(approval.command_id, set()).add(approval.drone_id)
            if approval.command_id in self.command_metrics:
                self.command_metrics[approval.command_id]["peer_verify_times_ms"].append(
                    round(elapsed * 1000, 3)
                )
        else:
            self.last_rejection_reason = f"Invalid signature from peer {approval.drone_id}"

        return is_valid, elapsed

    def provide_share(self, command_id: str) -> ShareMessage:
        """
        Provide this drone's Shamir share signed for the given command.
        If mesh_key is configured, the share coordinates (x, y) are encrypted using
        ChaCha20-Poly1305 AEAD broadcast encryption with anti-replay timestamp & nonce,
        ensuring complete wire confidentiality on the MQTT broadcast channel.
        """
        now = time.time()
        if self.mesh_key:
            # Broadcast Encryption: Encrypt (x, y) payload
            share_payload = {"x": self.share[0], "y": self.share[1]}
            aad = f"SHARE:{command_id}:{self.drone_id}:{now}".encode("utf-8")
            nonce, ciphertext = encrypt_payload(self.mesh_key, share_payload, aad=aad)

            share_msg = ShareMessage(
                command_id=command_id,
                drone_id=self.drone_id,
                x=0,
                y=0,
                timestamp=now,
                nonce_hex=nonce.hex(),
                ciphertext_hex=ciphertext.hex(),
                is_encrypted=True,
            )
        else:
            share_msg = ShareMessage(
                command_id=command_id,
                drone_id=self.drone_id,
                x=self.share[0],
                y=self.share[1],
                timestamp=now,
                is_encrypted=False,
            )

        sig = self.signer.sign(self.private_key, share_msg.digest())
        return share_msg.with_signature(sig)

    def receive_share(
        self,
        share_msg: ShareMessage,
        current_time: Optional[float] = None,
    ) -> bool:
        """
        Verify peer share signature, anti-replay freshness, decrypt AEAD ciphertext if encrypted,
        and store verified share coordinates for local threshold reconstruction.
        """
        # 1. Anti-Replay check if timestamp is present
        share_identifier = ""
        if share_msg.timestamp > 0.0:
            share_identifier = f"SHARE:{share_msg.command_id}:{share_msg.drone_id}"
            is_fresh, reason = self.anti_replay.check_freshness(
                share_identifier, share_msg.timestamp, current_time=current_time
            )
            if not is_fresh:
                self.last_rejection_reason = reason
                return False

        # 2. Check Trust Registry
        if not self.trust_registry.is_trusted(share_msg.drone_id):
            self.last_rejection_reason = f"Untrusted drone: {share_msg.drone_id}"
            return False

        peer_pk = self.trust_registry.get_public_key(share_msg.drone_id)
        if not peer_pk:
            self.last_rejection_reason = f"Missing public key for drone: {share_msg.drone_id}"
            return False

        # 3. Falcon-512 Signature verification
        sig_bytes = bytes.fromhex(share_msg.signature_hex)
        if not self.signer.verify(peer_pk, share_msg.digest(), sig_bytes):
            self.last_rejection_reason = f"Invalid signature from peer {share_msg.drone_id}"
            return False

        # 4. Decrypt share if encrypted
        if share_msg.is_encrypted:
            if not self.mesh_key:
                self.last_rejection_reason = "Cannot decrypt share: node has no mesh_key configured"
                return False

            try:
                nonce = bytes.fromhex(share_msg.nonce_hex)
                ciphertext = bytes.fromhex(share_msg.ciphertext_hex)
                aad = f"SHARE:{share_msg.command_id}:{share_msg.drone_id}:{share_msg.timestamp}".encode("utf-8")
                share_coords = decrypt_payload(self.mesh_key, nonce, ciphertext, aad=aad)
                share_x = int(share_coords["x"])
                share_y = int(share_coords["y"])
            except Exception as e:
                self.last_rejection_reason = f"Decryption/AEAD authentication failure for share from {share_msg.drone_id}: {e}"
                return False
        else:
            share_x = share_msg.x
            share_y = share_msg.y

        # 5. Record verified identifier in anti-replay cache
        if share_identifier and share_msg.timestamp > 0.0:
            self.anti_replay.record_seen(share_identifier, share_msg.timestamp, current_time=current_time)

        self.last_rejection_reason = None
        stored = self.collected_shares.setdefault(share_msg.command_id, [])
        if not any(s[0] == share_x for s in stored):
            stored.append((share_x, share_y))
        return True

    def can_execute(self, command_id: str) -> bool:
        """Check if local threshold condition is satisfied."""
        approvals = self.peer_approvals.get(command_id, set())
        shares = self.collected_shares.get(command_id, [])
        return len(approvals) >= self.threshold and len(shares) >= self.threshold

    def execute_command(self, command_id: str) -> Optional[Dict[str, Any]]:
        """
        Reconstruct mission key locally from collected shares and decrypt the command payload.
        Instruments metrics for Lagrange reconstruction and AEAD decryption.
        """
        if not self.can_execute(command_id):
            return None

        command = self.known_commands.get(command_id)
        if not command:
            return None

        shares = self.collected_shares[command_id][: self.threshold]

        recon_start = time.perf_counter()
        reconstructed_key_int = reconstruct_secret(shares)
        recon_elapsed = time.perf_counter() - recon_start

        try:
            mission_key = reconstructed_key_int.to_bytes(32, byteorder="big")
        except OverflowError:
            return None

        nonce = bytes.fromhex(command.nonce_hex)
        ciphertext = bytes.fromhex(command.ciphertext_hex)
        aad = bytes.fromhex(command.aad_hex)

        decrypt_start = time.perf_counter()
        try:
            payload = decrypt_payload(mission_key, nonce, ciphertext, aad=aad)
            decrypt_elapsed = time.perf_counter() - decrypt_start

            # Calculate end-to-end consensus time
            exec_time = time.time()
            total_consensus_time = (exec_time - command.timestamp) * 1000

            if command_id in self.command_metrics:
                m = self.command_metrics[command_id]
                m["reconstruct_time_ms"] = round(recon_elapsed * 1000, 3)
                m["decrypt_time_ms"] = round(decrypt_elapsed * 1000, 3)
                m["total_consensus_time_ms"] = round(total_consensus_time, 2)
                m["executed_timestamp"] = exec_time
                m["approvals_count"] = len(self.peer_approvals.get(command_id, set()))
                m["shares_count"] = len(self.collected_shares.get(command_id, []))

            return payload
        except Exception:
            return None

    def get_metrics(self, command_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve recorded performance metrics for a given command."""
        return self.command_metrics.get(command_id)
