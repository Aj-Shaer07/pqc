"""Data models and serialization for swarm protocol messages."""

import hashlib
import json
from dataclasses import dataclass
from typing import Dict, Any, Optional, Tuple


@dataclass(frozen=True)
class CommandMessage:
    """Represents a mission command broadcast from the Ground Station to the swarm."""
    command_id: str
    timestamp: float
    nonce_hex: str
    aad_hex: str
    ciphertext_hex: str
    gs_signature_hex: str = ""

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
        return {
            "command_id": self.command_id,
            "timestamp": self.timestamp,
            "nonce_hex": self.nonce_hex,
            "aad_hex": self.aad_hex,
            "ciphertext_hex": self.ciphertext_hex,
            "gs_signature_hex": self.gs_signature_hex,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CommandMessage":
        return cls(
            command_id=data["command_id"],
            timestamp=float(data["timestamp"]),
            nonce_hex=data["nonce_hex"],
            aad_hex=data["aad_hex"],
            ciphertext_hex=data["ciphertext_hex"],
            gs_signature_hex=data.get("gs_signature_hex", ""),
        )

    def with_signature(self, signature_bytes: bytes) -> "CommandMessage":
        return CommandMessage(
            command_id=self.command_id,
            timestamp=self.timestamp,
            nonce_hex=self.nonce_hex,
            aad_hex=self.aad_hex,
            ciphertext_hex=self.ciphertext_hex,
            gs_signature_hex=signature_bytes.hex(),
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
    """Represents a Shamir secret share published by a drone for key reconstruction."""
    command_id: str
    drone_id: str
    x: int
    y: int
    signature_hex: str = ""

    def canonical_signing_bytes(self) -> bytes:
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
        return {
            "command_id": self.command_id,
            "drone_id": self.drone_id,
            "x": self.x,
            "y": self.y,
            "signature_hex": self.signature_hex,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ShareMessage":
        return cls(
            command_id=data["command_id"],
            drone_id=data["drone_id"],
            x=int(data["x"]),
            y=int(data["y"]),
            signature_hex=data.get("signature_hex", ""),
        )

    def with_signature(self, signature_bytes: bytes) -> "ShareMessage":
        return ShareMessage(
            command_id=self.command_id,
            drone_id=self.drone_id,
            x=self.x,
            y=self.y,
            signature_hex=signature_bytes.hex(),
        )
