#!/usr/bin/env python3
"""Ground Station Container Daemon with MQTT PQC Command Dispatch."""

import logging
import os
import secrets
import signal
import sys
import time
from typing import Dict, Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("GroundStationDaemon")

from pqc_swarm import GroundStationNode, generate_mission_key, generate_shares
from pqc_swarm.networking import (
    SwarmMQTTTransport,
    TOPIC_COMMANDS,
    TOPIC_REGISTRY,
    TOPIC_TELEMETRY,
)

running = True


def signal_handler(sig, frame):
    global running
    logger.info("Termination signal received. Shutting down Ground Station...")
    running = False


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def main():
    broker_host = os.getenv("MQTT_BROKER", "localhost")
    broker_port = int(os.getenv("MQTT_PORT", "1883"))
    threshold = int(os.getenv("THRESHOLD", "3"))
    expected_drones = int(os.getenv("NUM_DRONES", "0"))
    mesh_key_hex = os.getenv("SWARM_MESH_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    if mesh_key_hex:
        logger.info("🔐 Swarm Broadcast Mesh Key active (Wire Confidentiality enabled across swarm).")

    logger.info("🛰️ Initializing Ground Station Node...")
    gs = GroundStationNode()

    transport = SwarmMQTTTransport(
        client_id=f"GROUND_STATION_{secrets.token_hex(4)}",
        broker_host=broker_host,
        broker_port=broker_port,
    )

    registered_drones: Dict[str, str] = {}
    assigned_shares: Dict[str, Any] = {}
    acknowledged_drones = set()

    mission_key = generate_mission_key()
    mission_key_int = int.from_bytes(mission_key, byteorder="big")

    def broadcast_registry():
        transport.publish(TOPIC_REGISTRY, {
            "assigned_shares": assigned_shares,
            "gs_public_key_hex": gs.public_key.hex(),
            "peer_registry": dict(registered_drones),
        })

    def on_telemetry(topic: str, data: Dict[str, Any]):
        drone_id = data.get("drone_id")
        if data.get("event") == "SECURITY_ALERT":
            alert_type = data.get("alert_type")
            reason = data.get("reason")
            logger.warning(f"[GS] 🚨 SECURITY ALERT from {drone_id}: {alert_type} ({reason})")
            return

        cid = data.get("command_id")
        status = data.get("status")
        metrics = data.get("metrics", {})
        acknowledged_drones.add(drone_id)

        consensus_ms = metrics.get("total_consensus_time_ms")
        gs_verify_ms = metrics.get("gs_verify_time_ms")
        recon_ms = metrics.get("reconstruct_time_ms")
        metric_str = f" | Latency: consensus={consensus_ms}ms, verify={gs_verify_ms}ms, sss={recon_ms}ms" if consensus_ms else ""
        logger.info(f"[GS] 📡 Received telemetry ACK from {drone_id} for command {cid} (Status: {status}{metric_str})")

    def on_registry(topic: str, data: Dict[str, Any]):
        drone_id = data.get("drone_id")
        pk_hex = data.get("public_key_hex")
        if drone_id and pk_hex:
            is_new = drone_id not in registered_drones
            registered_drones[drone_id] = pk_hex
            if is_new:
                logger.info(f"[GS] 📋 Registered active drone in swarm: {drone_id} (Total: {len(registered_drones)})")

    transport.register_handler(TOPIC_TELEMETRY, on_telemetry)
    transport.register_handler(TOPIC_REGISTRY, on_registry)

    transport.connect()

    # Announce GS Public Key repeatedly during initialization so newly booting drones receive it
    logger.info("[GS] 📢 Announcing GS Falcon-512 Public Key to swarm...")
    for _ in range(3):
        transport.publish(TOPIC_REGISTRY, {
            "gs_public_key_hex": gs.public_key.hex(),
        })
        time.sleep(1)

    # Wait dynamically for drone containers to initialize and register
    target_count = expected_drones if expected_drones > 0 else threshold
    logger.info(f"[GS] ⏳ Waiting for drone containers to discover network and register (Target: {target_count} drones)...")
    wait_start = time.time()
    last_count = 0
    stable_seconds = 0
    while time.time() - wait_start < 25.0:
        time.sleep(1.0)
        curr = len(registered_drones)
        if expected_drones > 0 and curr >= expected_drones:
            break
        if curr >= threshold and curr == last_count:
            stable_seconds += 1
            if stable_seconds >= 3:
                break
        else:
            stable_seconds = 0
            last_count = curr
            if curr > 0:
                logger.info(f"[GS] 📋 Swarm discovery progress: {curr}/{target_count} drone(s) registered.")

    num_drones = max(len(registered_drones), threshold)
    logger.info(f"[GS] 🗝️ Active swarm established with {num_drones} drones. Generating exact (k={threshold}, n={num_drones}) Shamir shares...")
    shares = generate_shares(mission_key_int, threshold=threshold, num_shares=num_drones)

    # Assign each registered drone its exact unique coordinate (1..n)
    for idx, d_id in enumerate(registered_drones.keys()):
        assigned_shares[d_id] = (shares[idx][0], shares[idx][1])
        logger.info(f"[GS] 📦 Assigned share (x={shares[idx][0]}) to {d_id}")

    broadcast_registry()

    command_seq = 0

    def dispatch_mission(action: str = "MISSION_RECON"):
        nonlocal command_seq
        command_seq += 1
        now = time.time()
        payload = {
            "action": action,
            "seq": command_seq,
            "waypoints": [
                {"lat": 37.7749 + (command_seq * 0.001), "lon": -122.4194, "alt": 100},
                {"lat": 37.7755, "lon": -122.4180 + (command_seq * 0.001), "alt": 120},
            ],
            "timestamp": now,
        }
 
        broadcast_registry()
        logger.info(f"[GS] 🔒 Encrypting (ChaCha20-Poly1305) & signing (Falcon-512) mission command #{command_seq} ({action})...")
        cmd, sign_time = gs.create_command(payload, mission_key)
        logger.info(f"[GS] Command created: {cmd.command_id} (Sign time: {sign_time*1000:.2f}ms)")
        logger.info(f"[GS] 🚀 Broadcasting command to '{TOPIC_COMMANDS}'...")
        transport.publish(TOPIC_COMMANDS, cmd.to_dict())

    # Listen for on-demand mission triggers (e.g. from adversary or test harnesses)
    def on_trigger(topic: str, data: Dict[str, Any]):
        reason = data.get("reason", "manual_trigger")
        logger.info(f"[GS] ⚡ Live mission dispatch requested ({reason}).")
        dispatch_mission(f"MISSION_{reason.upper()}")

    transport.register_handler("swarm/trigger", on_trigger)

    time.sleep(2)

    # Issue Initial Mission Command
    dispatch_mission("MISSION_INITIAL_RECON")

    # Periodic dispatch loop (every 20s) to keep live swarm active
    last_dispatch = time.time()
    dispatch_interval = int(os.getenv("DISPATCH_INTERVAL", "20"))

    logger.info(f"[GS] Active and listening for swarm events (Periodic waypoint interval: {dispatch_interval}s)...")
    while running:
        time.sleep(1)
        if dispatch_interval > 0 and (time.time() - last_dispatch >= dispatch_interval):
            last_dispatch = time.time()
            logger.info("[GS] ⏰ Dispatching periodic waypoint patrol...")
            dispatch_mission("MISSION_PATROL_WAYPOINT")

    transport.disconnect()
    logger.info("[GS] Ground Station stopped.")



if __name__ == "__main__":
    main()
