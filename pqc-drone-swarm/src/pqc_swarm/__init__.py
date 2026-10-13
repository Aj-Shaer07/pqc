"""
Post-Quantum Cryptographic Drone Swarm Coordination Framework.

A decentralized, post-quantum threshold cryptography framework for autonomous drone swarms.
Features:
- Falcon-512 digital signatures (NIST Round 3 PQC standard)
- Shamir's Secret Sharing (k-out-of-n threshold reconstruction)
- ChaCha20-Poly1305 AEAD authenticated encryption
- Autonomous drone nodes with local threshold verification (no centralized threshold engine)
"""

from pqc_swarm.nodes.drone import DroneNode
from pqc_swarm.nodes.ground_station import GroundStationNode
from pqc_swarm.models.messages import CommandMessage, ApprovalMessage, ShareMessage
from pqc_swarm.models.registry import TrustRegistry
from pqc_swarm.crypto.falcon import FalconSigner
from pqc_swarm.crypto.sss import generate_shares, reconstruct_secret, PRIME
from pqc_swarm.crypto.aead import generate_mission_key, encrypt_payload, decrypt_payload
from pqc_swarm.crypto.anti_replay import AntiReplayFilter
from pqc_swarm.sim.in_memory_sim import run_decentralized_simulation

__version__ = "0.3.0"

__all__ = [
    # Nodes
    "DroneNode",
    "GroundStationNode",
    # Models
    "CommandMessage",
    "ApprovalMessage",
    "ShareMessage",
    "TrustRegistry",
    # Crypto
    "FalconSigner",
    "generate_shares",
    "reconstruct_secret",
    "PRIME",
    "generate_mission_key",
    "encrypt_payload",
    "decrypt_payload",
    "AntiReplayFilter",
    # Simulation
    "run_decentralized_simulation",
]
