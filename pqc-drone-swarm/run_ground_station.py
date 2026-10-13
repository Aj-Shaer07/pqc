#!/usr/bin/env python3
"""Ground Station Container Daemon with MQTT PQC Command Dispatch."""

import logging
import os
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
    mesh_key_hex = os.getenv("SWARM_MESH_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    if mesh_key_hex:
        logger.info("🔐 Swarm Broadcast Mesh Key active (Wire Confidentiality enabled across swarm).")

    logger.info("🛰️ Initializing Ground Station Node...")
    gs = GroundStationNode()

    transport = SwarmMQTTTransport(
        client_id="GROUND_STATION",
        broker_host=broker_host,
        broker_port=broker_port,
    )

    registered_drones = {}
    acknowledged_drones = set()

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
            registered_drones[drone_id] = pk_hex
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

    # Wait for drone containers to initialize and register
    logger.info("[GS] ⏳ Waiting 6 seconds for drone containers to discover network and register...")
    time.sleep(6)

    # Prepare Mission Key and Shamir Shares
    mission_key = generate_mission_key()
    mission_key_int = int.from_bytes(mission_key, byteorder="big")

    num_drones = max(len(registered_drones), threshold)
    shares = generate_shares(mission_key_int, threshold=threshold, num_shares=num_drones)

    # Assign each registered drone a unique share
    assigned_shares = {}
    for idx, d_id in enumerate(registered_drones.keys()):
        assigned_shares[d_id] = (shares[idx][0], shares[idx][1])

    logger.info(f"[GS] 🗝️ Generated Shamir Shares (k={threshold}, n={num_drones}). Distributing to registered drones...")
    transport.publish(TOPIC_REGISTRY, {
        "assigned_shares": assigned_shares,
        "gs_public_key_hex": gs.public_key.hex(),
    })

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
