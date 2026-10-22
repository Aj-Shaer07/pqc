"""Data models and serialization for swarm protocol messages."""

import hashlib
import json
from dataclasses import dataclass
from typing import Dict, Any, Optional, Tuple, List


@dataclass(frozen=True)
class CommandMessage:
    """Represents a mission command broadcast from the Ground Station to the swarm."""
    command_id: str
    timestamp: float
    nonce_hex: str
    aad_hex: str
    ciphertext_hex: str
    gs_signature_hex: str = ""
    gs_signatures: Optional[Tuple[Tuple[str, str], ...]] = None  # Tuple of (operator_id, signature_hex)

    def canonical_signing_bytes(self) -> bytes:
        """Deterministic canonical representation for Falcon signing/verification."""
        data = {
            "aad_hex": self.aad_hex,
            "ciphertext_hex": self.ciphertext_hex,
            "command_id": self.command_id,
            "nonce_hex": self.nonce_hex,
            "timestamp": self.timestamp,
        }
        return json.dumps(data, sort_keys=True).encode("utf-8")

    def digest(self) -> bytes:
        """SHA-256 digest of canonical message content."""
        return hashlib.sha256(self.canonical_signing_bytes()).digest()

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "command_id": self.command_id,
            "timestamp": self.timestamp,
            "nonce_hex": self.nonce_hex,
            "aad_hex": self.aad_hex,
            "ciphertext_hex": self.ciphertext_hex,
            "gs_signature_hex": self.gs_signature_hex,
        }
        if self.gs_signatures:
            d["gs_signatures"] = [
                {"operator_id": op, "signature_hex": sig}
                for op, sig in self.gs_signatures
            ]
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CommandMessage":
        raw_sigs = data.get("gs_signatures")
        parsed_sigs = None
        if raw_sigs:
            parsed_sigs = tuple(
                (item["operator_id"], item["signature_hex"])
                for item in raw_sigs
            )
        return cls(
            command_id=data["command_id"],
            timestamp=float(data["timestamp"]),
            nonce_hex=data["nonce_hex"],
            aad_hex=data["aad_hex"],
            ciphertext_hex=data["ciphertext_hex"],
            gs_signature_hex=data.get("gs_signature_hex", ""),
            gs_signatures=parsed_sigs,
        )

    def with_signature(self, signature_bytes: bytes) -> "CommandMessage":
        return CommandMessage(
            command_id=self.command_id,
            timestamp=self.timestamp,
            nonce_hex=self.nonce_hex,
            aad_hex=self.aad_hex,
            ciphertext_hex=self.ciphertext_hex,
            gs_signature_hex=signature_bytes.hex(),
            gs_signatures=self.gs_signatures,
        )

    def with_operator_signatures(self, signatures: List[Tuple[str, bytes]]) -> "CommandMessage":
        """Attach multiple operator signatures to the command message."""
        sigs_tuple = tuple((op_id, sig_bytes.hex()) for op_id, sig_bytes in signatures)
        primary_sig = signatures[0][1].hex() if signatures else self.gs_signature_hex
        return CommandMessage(
            command_id=self.command_id,
            timestamp=self.timestamp,
            nonce_hex=self.nonce_hex,
            aad_hex=self.aad_hex,
            ciphertext_hex=self.ciphertext_hex,
            gs_signature_hex=primary_sig,
            gs_signatures=sigs_tuple,
        )


@dataclass(frozen=True)
class ApprovalMessage:
    """Represents an independent cryptographic approval sent by a drone."""
    command_id: str
    drone_id: str
    timestamp: float
    signature_hex: str

    def canonical_signing_bytes(self) -> bytes:
        data = {
            "command_id": self.command_id,
            "drone_id": self.drone_id,
            "timestamp": self.timestamp,
        }
        return json.dumps(data, sort_keys=True).encode("utf-8")

    def digest(self) -> bytes:
        return hashlib.sha256(self.canonical_signing_bytes()).digest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command_id": self.command_id,
            "drone_id": self.drone_id,
            "timestamp": self.timestamp,
            "signature_hex": self.signature_hex,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ApprovalMessage":
        return cls(
            command_id=data["command_id"],
            drone_id=data["drone_id"],
            timestamp=float(data["timestamp"]),
            signature_hex=data["signature_hex"],
        )


@dataclass(frozen=True)
class ShareMessage:
    """
    Represents a Shamir secret share published by a drone for key reconstruction.
    Supports ChaCha20-Poly1305 AEAD broadcast encryption to ensure wire confidentiality.
    When is_encrypted=True, (x, y) coordinates are never exposed in plaintext over the wire.
    """
    command_id: str
    drone_id: str
    x: int = 0
    y: int = 0
    timestamp: float = 0.0
    nonce_hex: str = ""
    ciphertext_hex: str = ""
    signature_hex: str = ""
    is_encrypted: bool = False

    def canonical_signing_bytes(self) -> bytes:
        if self.is_encrypted:
            data = {
                "ciphertext_hex": self.ciphertext_hex,
                "command_id": self.command_id,
                "drone_id": self.drone_id,
                "is_encrypted": True,
                "nonce_hex": self.nonce_hex,
                "timestamp": self.timestamp,
            }
        else:
            data = {
                "command_id": self.command_id,
                "drone_id": self.drone_id,
                "x": self.x,
                "y": self.y,
            }
        return json.dumps(data, sort_keys=True).encode("utf-8")

    def digest(self) -> bytes:
        return hashlib.sha256(self.canonical_signing_bytes()).digest()

    def to_dict(self) -> Dict[str, Any]:
        if self.is_encrypted:
            # Wire confidentiality: Never leak x or y in plaintext
            return {
                "command_id": self.command_id,
                "drone_id": self.drone_id,
                "timestamp": self.timestamp,
                "nonce_hex": self.nonce_hex,
                "ciphertext_hex": self.ciphertext_hex,
                "signature_hex": self.signature_hex,
                "is_encrypted": True,
            }
        return {
            "command_id": self.command_id,
            "drone_id": self.drone_id,
            "x": self.x,
            "y": self.y,
            "signature_hex": self.signature_hex,
            "is_encrypted": False,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ShareMessage":
        is_enc = bool(data.get("is_encrypted", False))
        if is_enc:
            return cls(
                command_id=data["command_id"],
                drone_id=data["drone_id"],
                timestamp=float(data.get("timestamp", 0.0)),
                nonce_hex=data.get("nonce_hex", ""),
                ciphertext_hex=data.get("ciphertext_hex", ""),
                signature_hex=data.get("signature_hex", ""),
                is_encrypted=True,
            )
        return cls(
            command_id=data["command_id"],
            drone_id=data["drone_id"],
            x=int(data["x"]),
            y=int(data["y"]),
            signature_hex=data.get("signature_hex", ""),
            is_encrypted=False,
        )

    def with_signature(self, signature_bytes: bytes) -> "ShareMessage":
        return ShareMessage(
            command_id=self.command_id,
            drone_id=self.drone_id,
            x=self.x,
            y=self.y,
            timestamp=self.timestamp,
            nonce_hex=self.nonce_hex,
            ciphertext_hex=self.ciphertext_hex,
            signature_hex=signature_bytes.hex(),
            is_encrypted=self.is_encrypted,
        )

