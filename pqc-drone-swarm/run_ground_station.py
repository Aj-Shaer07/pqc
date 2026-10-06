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
        cid = data.get("command_id")
        status = data.get("status")
        acknowledged_drones.add(drone_id)
        logger.info(f"[GS] 📡 Received telemetry ACK from {drone_id} for command {cid} (Status: {status})")

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

    time.sleep(2)

    # Issue a Post-Quantum Encrypted Mission Command
    payload = {
        "action": "MISSION_RECON",
        "waypoints": [
            {"lat": 37.7749, "lon": -122.4194, "alt": 100},
            {"lat": 37.7755, "lon": -122.4180, "alt": 120},
        ],
        "timestamp": time.time(),
    }

    logger.info("[GS] 🔒 Encrypting (ChaCha20-Poly1305) and signing (Falcon-512) mission command...")
    cmd, sign_time = gs.create_command(payload, mission_key)
    logger.info(f"[GS] Command created: {cmd.command_id} (Sign time: {sign_time*1000:.2f}ms)")

    logger.info(f"[GS] 🚀 Broadcasting command to '{TOPIC_COMMANDS}'...")
    transport.publish(TOPIC_COMMANDS, cmd.to_dict())

    # Monitor swarm progress
    while running:
        time.sleep(1)

    transport.disconnect()
    logger.info("[GS] Ground Station stopped.")


if __name__ == "__main__":
    main()
