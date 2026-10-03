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

    logger.info("Initializing Ground Station Node...")
    gs = GroundStationNode()

    transport = SwarmMQTTTransport(
        client_id="GROUND_STATION",
        broker_host=broker_host,
        broker_port=broker_port,
    )

    acknowledged_drones = set()

    def on_telemetry(topic: str, data: Dict[str, Any]):
        drone_id = data.get("drone_id")
        cid = data.get("command_id")
        status = data.get("status")
        acknowledged_drones.add(drone_id)
        logger.info(f"[GS] 📡 Received telemetry ACK from {drone_id} for command {cid} (Status: {status})")

    def on_registry(topic: str, data: Dict[str, Any]):
        drone_id = data.get("drone_id")
        logger.info(f"[GS] 📋 Registered active drone in swarm: {drone_id}")

    transport.register_handler(TOPIC_TELEMETRY, on_telemetry)
    transport.register_handler(TOPIC_REGISTRY, on_registry)

    transport.connect()

    # Announce GS Public Key
    time.sleep(2)
    transport.publish(TOPIC_REGISTRY, {
        "gs_public_key_hex": gs.public_key.hex(),
    })

    # Wait for swarm discovery
    logger.info("[GS] Waiting 5 seconds for drone containers to initialize...")
    time.sleep(5)

    # Issue a Post-Quantum Encrypted Mission Command
    mission_key = generate_mission_key()
    payload = {
        "action": "MISSION_RECON",
        "waypoints": [
            {"lat": 37.7749, "lon": -122.4194, "alt": 100},
            {"lat": 37.7755, "lon": -122.4180, "alt": 120},
        ],
        "timestamp": time.time(),
    }

    logger.info("[GS] Encrypting and signing PQC mission command with Falcon-512...")
    cmd, sign_time = gs.create_command(payload, mission_key)
    logger.info(f"[GS] Command created: {cmd.command_id} (Sign time: {sign_time*1000:.2f}ms)")

    logger.info(f"[GS] 🚀 Broadcasting command to '{TOPIC_COMMANDS}'...")
    transport.publish(TOPIC_COMMANDS, cmd.to_dict())

    # Keep alive and monitor telemetry
    while running:
        time.sleep(1)

    transport.disconnect()
    logger.info("[GS] Ground Station stopped.")


if __name__ == "__main__":
    main()
