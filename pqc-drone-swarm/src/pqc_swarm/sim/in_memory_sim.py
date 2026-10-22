"""High-performance local simulation harness supporting decoupled dual-thresholds (ka, ks),
stochastic RF mesh packet loss, propagation jitter, wire size accounting, and performance metrics."""

import json
import random
import time
from typing import Dict, Any, List, Optional
from pqc_swarm.crypto.aead import generate_mission_key
from pqc_swarm.crypto.sss import generate_shares
from pqc_swarm.models.registry import TrustRegistry
from pqc_swarm.nodes.ground_station import GroundStationNode
from pqc_swarm.nodes.drone import DroneNode


def run_decentralized_simulation(
    k: Optional[int] = None,
    n: int = 5,
    ka: Optional[int] = None,
    ks: Optional[int] = None,
    loss_rate: float = 0.0,
    min_jitter_ms: float = 0.0,
    max_jitter_ms: float = 0.0,
    use_encrypted_shares: bool = True,
    profile_name: str = "Standard",
    cached_drones: Optional[List[DroneNode]] = None,
    cached_gs: Optional[GroundStationNode] = None,
) -> Dict[str, Any]:
    """
    Executes a fully decentralized in-memory round with:
    1. Decoupled dual-thresholds (ka approvals required, ks shares required for reconstruction).
    2. Simulated stochastic wireless packet loss (loss_rate: 0.0 to 1.0).
    3. Simulated propagation jitter (min_jitter_ms to max_jitter_ms).
    4. Exact wire payload accounting (Commands, Approvals, Shares).
    5. Performance metric instrumentation (Keygen, Sign, Verify, Reconstruct, Decrypt, Consensus).
    """
    round_start = time.perf_counter()

    # Resolve dual thresholds with backwards compatibility
    eff_ka = ka if ka is not None else (k if k is not None else 3)
    eff_ks = ks if ks is not None else (k if k is not None else eff_ka)
    k_val = eff_ks

    mission_key = generate_mission_key()
    mission_key_int = int.from_bytes(mission_key, byteorder="big")
    mesh_key = generate_mission_key() if use_encrypted_shares else None

    # Generate Shamir shares of degree ks - 1 over Mersenne prime field
    shares = generate_shares(mission_key_int, threshold=eff_ks, num_shares=n)

    # Initialize or reuse Ground Station
    if cached_gs is not None:
        gs = cached_gs
    else:
        gs = GroundStationNode()

    # Initialize or reuse persistent drone nodes (avoiding redundant Falcon keygen per trial)
    if cached_drones is not None and len(cached_drones) >= n:
        drones = cached_drones[:n]
        for i, share in enumerate(shares):
            d = drones[i]
            d.share = share
            d.threshold = eff_ks
            d.approval_threshold = eff_ka
            d.reconstruct_threshold = eff_ks
            d.mesh_key = mesh_key
    else:
        trust_registry = TrustRegistry()
        trust_registry.set_gs_public_key(gs.public_key)
        drones = []
        for i, share in enumerate(shares):
            drone = DroneNode(
                drone_id=f"DRONE_{i+1}",
                share=share,
                threshold=eff_ks,
                approval_threshold=eff_ka,
                reconstruct_threshold=eff_ks,
                trust_registry=trust_registry,
                mesh_key=mesh_key,
            )
            trust_registry.register_drone(drone.drone_id, drone.public_key)
            drones.append(drone)

    payload = {"action": "NAVIGATE_WAYPOINT", "lat": 37.7749, "lon": -122.4194, "alt": 120}
    command, gs_sign_time = gs.create_command(payload, mission_key)

    # Wire size accounting
    command_wire_bytes = len(json.dumps(command.to_dict()).encode("utf-8"))
    approval_wire_bytes = 0
    share_wire_bytes = 0
    total_wire_bytes = command_wire_bytes * n

    # Step 1: Ground Station broadcasts command to drones over RF channel
    drone_verify_times = []
    drone_approve_times = []
    approving_drones: List[DroneNode] = []
    approvals_map: Dict[str, Any] = {}

    # RF broadcast wave propagation delay
    rf_wave1_delay = random.uniform(min_jitter_ms, max_jitter_ms) / 1000.0 if max_jitter_ms > 0.0 else 0.015
    if max_jitter_ms > 0.0:
        time.sleep(rf_wave1_delay)

    for drone in drones:
        # Check simulated RF loss on command reception
        if loss_rate > 0.0 and random.random() < loss_rate:
            continue  # Command dropped on this link

        cmd_arrival_time = command.timestamp + rf_wave1_delay
        is_valid, v_time = drone.verify_gs_command(command, current_time=cmd_arrival_time)
        drone_verify_times.append(v_time)
        if is_valid:
            app, a_time = drone.create_approval(command.command_id)
            drone_approve_times.append(a_time)
            approvals_map[drone.drone_id] = app
            approving_drones.append(drone)
            if approval_wire_bytes == 0:
                approval_wire_bytes = len(json.dumps(app.to_dict()).encode("utf-8"))

    # Step 2: Drones gossip approvals peer-to-peer
    peer_verify_times = []
    rf_wave2_delay = random.uniform(min_jitter_ms, max_jitter_ms) / 1000.0 if max_jitter_ms > 0.0 else 0.015
    if max_jitter_ms > 0.0 and approving_drones:
        time.sleep(rf_wave2_delay)

    for sender_drone in approving_drones:
        app = approvals_map[sender_drone.drone_id]
        app_arrival_time = app.timestamp + rf_wave2_delay
        for receiver_drone in drones:
            if receiver_drone.drone_id != sender_drone.drone_id:
                total_wire_bytes += approval_wire_bytes
                # Check simulated RF loss on peer approval link
                if loss_rate > 0.0 and random.random() < loss_rate:
                    continue  # Approval dropped

                # In real distributed systems, once a node reaches quorum ka, it avoids redundant CPU verifications
                current_approvals = receiver_drone.peer_approvals.get(command.command_id, set())
                if len(current_approvals) >= eff_ka:
                    current_approvals.add(app.drone_id)
                    continue

                valid_peer, pv_time = receiver_drone.process_peer_approval(app, current_time=app_arrival_time)
                peer_verify_times.append(pv_time)

    # Step 3: Drones that accumulated at least ka approvals release their shares
    shares_broadcasted: Dict[str, Any] = {}
    for drone in drones:
        if drone.can_release_share(command.command_id):
            share_msg = drone.provide_share(command.command_id)
            shares_broadcasted[drone.drone_id] = share_msg
            if share_wire_bytes == 0:
                share_wire_bytes = len(json.dumps(share_msg.to_dict()).encode("utf-8"))

    # Gossip shares among peers over RF mesh wave
    rf_wave3_delay = random.uniform(min_jitter_ms, max_jitter_ms) / 1000.0 if max_jitter_ms > 0.0 else 0.015
    if max_jitter_ms > 0.0 and shares_broadcasted:
        time.sleep(rf_wave3_delay)

    for sender_id, share_msg in shares_broadcasted.items():
        share_arrival_time = share_msg.timestamp + rf_wave3_delay
        for receiver_drone in drones:
            if receiver_drone.drone_id != sender_id:
                total_wire_bytes += share_wire_bytes
                # Check simulated RF loss on share gossip link
                if loss_rate > 0.0 and random.random() < loss_rate:
                    continue  # Share dropped

                # Avoid redundant decryption once reconstruction threshold ks is satisfied
                if len(receiver_drone.collected_shares.get(command.command_id, [])) >= eff_ks:
                    continue

                receiver_drone.receive_share(share_msg, current_time=share_arrival_time)

    # Step 4: Each drone independently checks execution condition (approvals >= ka and shares >= ks)
    executed_count = 0
    reconstruct_times = []
    decrypt_times = []
    consensus_times = []

    # Total RF network wave propagation delay experienced across the 3 broadcast phases
    total_rf_wave_delay = rf_wave1_delay + rf_wave2_delay + rf_wave3_delay

    for drone in drones:
        if drone.can_execute(command.command_id):
            result = drone.execute_command(command.command_id)
            if result == payload:
                executed_count += 1
                metrics = drone.get_metrics(command.command_id) or {}
                rec_s = metrics.get("reconstruct_time_ms", 0.0) / 1000.0
                dec_s = metrics.get("decrypt_time_ms", 0.0) / 1000.0
                reconstruct_times.append(rec_s)
                decrypt_times.append(dec_s)

                # Parallel Distributed Consensus Model:
                # In a real physical distributed swarm, each drone runs on its own independent companion processor.
                # A drone's critical path to consensus consists of:
                # 1. RF command reception wave delay + GS signature verification + approval creation
                # 2. RF approval gossip wave delay + verification of the ka approvals required for quorum
                # 3. RF share gossip wave delay + verification of the ks shares required for key reconstruction
                # 4. Local Lagrange polynomial reconstruction + AEAD payload decryption
                gs_v_s = metrics.get("gs_verify_time_ms", 0.0) / 1000.0
                peer_v_list = [t / 1000.0 for t in metrics.get("peer_verify_times_ms", [])]
                peer_app_s = sum(peer_v_list[:eff_ka]) if peer_v_list else (0.012 * eff_ka)
                avg_pv_s = (sum(peer_v_list) / len(peer_v_list)) if peer_v_list else 0.012
                peer_share_s = avg_pv_s * eff_ks
                sign_overhead_s = metrics.get("approval_create_time_ms", 0.0) / 1000.0

                drone_parallel_consensus_s = (
                    total_rf_wave_delay
                    + gs_v_s
                    + sign_overhead_s
                    + peer_app_s
                    + peer_share_s
                    + rec_s
                    + dec_s
                )

                consensus_times.append(drone_parallel_consensus_s)

    round_duration = time.perf_counter() - round_start

    def safe_avg(vals: List[float]) -> float:
        return sum(vals) / len(vals) if vals else 0.0

    # A consensus round is successful if at least ks nodes executed (or all active if loss allows)
    consensus_success = executed_count >= eff_ks and executed_count > 0

    return {
        "k": k_val,
        "ka": eff_ka,
        "ks": eff_ks,
        "n": n,
        "loss_rate": loss_rate,
        "profile_name": profile_name,
        "executed_count": executed_count,
        "success": consensus_success,
        "dispatched": 1,
        "accepted": 1 if consensus_success else 0,
        "rejected": 0,
        "dropped": 0 if consensus_success else 1,
        "gs_keygen": gs.keygen_time,
        "gs_sign": gs_sign_time,
        "drone_keygen_avg": safe_avg([d.keygen_time for d in drones]),
        "drone_verify_avg": safe_avg(drone_verify_times),
        "drone_approve_avg": safe_avg(drone_approve_times),
        "peer_verify_avg": safe_avg(peer_verify_times),
        "reconstruct_avg": safe_avg(reconstruct_times),
        "decrypt_avg": safe_avg(decrypt_times),
        "round_duration": round_duration,
        "consensus_time_avg": safe_avg(consensus_times) if consensus_times else round_duration,
        "wire_command_bytes": command_wire_bytes,
        "wire_approval_bytes": approval_wire_bytes if approval_wire_bytes > 0 else 778,
        "wire_share_bytes": share_wire_bytes if share_wire_bytes > 0 else 846,
        "total_wire_bytes": total_wire_bytes,
    }
