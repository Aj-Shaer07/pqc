"""High-performance local simulation harness matching implementation.py benchmarks."""

import time
import random
from typing import Dict, Any, List
from pqc_swarm.crypto.aead import generate_mission_key
from pqc_swarm.crypto.sss import generate_shares
from pqc_swarm.models.registry import TrustRegistry
from pqc_swarm.nodes.ground_station import GroundStationNode
from pqc_swarm.nodes.drone import DroneNode


def run_decentralized_simulation(k: int = 3, n: int = 5) -> Dict[str, Any]:
    """
    Executes a fully decentralized in-memory round:
    1. GS issues and signs command.
    2. Drones independently verify GS signature.
    3. Drones generate approvals and broadcast to peers.
    4. Each drone verifies peer approvals independently (no central threshold engine).
    5. Shares are distributed and validated.
    6. Each drone reconstructs mission key and decrypts locally.
    """
    trust_registry = TrustRegistry()
    mission_key = generate_mission_key()
    mission_key_int = int.from_bytes(mission_key, byteorder="big")

    shares = generate_shares(mission_key_int, threshold=k, num_shares=n)

    # Initialize drones
    drones: List[DroneNode] = []
    for i, share in enumerate(shares):
        drone = DroneNode(
            drone_id=f"DRONE_{i+1}",
            share=share,
            threshold=k,
            trust_registry=trust_registry,
        )
        drones.append(drone)

    # Initialize GS
    gs = GroundStationNode()
    trust_registry.set_gs_public_key(gs.public_key)

    payload = {"action": "NAVIGATE_WAYPOINT", "lat": 37.7749, "lon": -122.4194, "alt": 120}
    command, gs_sign_time = gs.create_command(payload, mission_key)

    # Step 1: Drones verify GS signature and issue approvals
    approvals = []
    drone_verify_times = []
    drone_approve_times = []

    for drone in drones:
        is_valid, v_time = drone.verify_gs_command(command)
        drone_verify_times.append(v_time)
        if is_valid:
            app, a_time = drone.create_approval(command.command_id)
            drone_approve_times.append(a_time)
            approvals.append(app)

    # Step 2: Drones independently receive and verify peer approvals
    peer_verify_times = []
    for drone in drones:
        for app in approvals:
            if app.drone_id != drone.drone_id:
                valid_peer, pv_time = drone.process_peer_approval(app)
                peer_verify_times.append(pv_time)

    # Step 3: Drones exchange shares until threshold k is met
    for sender_drone in drones[:k]:
        share_msg = sender_drone.provide_share(command.command_id)
        for receiver_drone in drones:
            if receiver_drone.drone_id != sender_drone.drone_id:
                receiver_drone.receive_share(share_msg)

    # Step 4: Each drone independently executes the command
    executed_count = 0
    for drone in drones:
        if drone.can_execute(command.command_id):
            result = drone.execute_command(command.command_id)
            if result == payload:
                executed_count += 1

    def safe_avg(vals: List[float]) -> float:
        return sum(vals) / len(vals) if vals else 0.0

    return {
        "k": k,
        "n": n,
        "executed_count": executed_count,
        "gs_keygen": gs.keygen_time,
        "gs_sign": gs_sign_time,
        "drone_keygen_avg": safe_avg([d.keygen_time for d in drones]),
        "drone_verify_avg": safe_avg(drone_verify_times),
        "drone_approve_avg": safe_avg(drone_approve_times),
        "peer_verify_avg": safe_avg(peer_verify_times),
    }
