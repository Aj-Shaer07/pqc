#!/usr/bin/env python3
"""Autonomous Drone Container Daemon with MQTT P2P Gossip."""

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
logger = logging.getLogger("DroneDaemon")

from pqc_swarm import DroneNode, TrustRegistry, CommandMessage, ApprovalMessage, ShareMessage
from pqc_swarm.networking import (
    SwarmMQTTTransport,
    TOPIC_COMMANDS,
    TOPIC_APPROVALS,
    TOPIC_SHARES,
    TOPIC_REGISTRY,
    TOPIC_TELEMETRY,
)

running = True


def signal_handler(sig, frame):
    global running
    logger.info("Termination signal received. Shutting down drone daemon...")
    running = False


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def main():
    broker_host = os.getenv("MQTT_BROKER", "localhost")
    broker_port = int(os.getenv("MQTT_PORT", "1883"))
    threshold = int(os.getenv("THRESHOLD", "3"))

    # Extract unique Drone ID from container hostname or env
    hostname = os.getenv("HOSTNAME", "node")[:8]
    drone_id = os.getenv("DRONE_ID", f"DRONE_{hostname}")

    logger.info(f"🚀 Initializing Autonomous Drone Node: {drone_id} (Threshold k={threshold})")

    trust_registry = TrustRegistry()
    
    # Initialize Drone with dummy share initially; real share provided via GS registry or derived
    # We assign dynamic share index based on hash or container instance
    node_index = abs(hash(drone_id)) % 1000 + 1
    # Temporary placeholder share until GS onboard handshake
    drone = DroneNode(
        drone_id=drone_id,
        share=(node_index, 0),
        threshold=threshold,
        trust_registry=trust_registry,
    )

    transport = SwarmMQTTTransport(
        client_id=drone_id,
        broker_host=broker_host,
        broker_port=broker_port,
    )

    # 1. Handle Registry: GS public key, peer public keys, and assigned shares
    def on_registry_received(topic: str, data: Dict[str, Any]):
        # Ground Station announcing its public key
        if "gs_public_key_hex" in data:
            gs_pk = bytes.fromhex(data["gs_public_key_hex"])
            trust_registry.set_gs_public_key(gs_pk)
            logger.info(f"[{drone_id}] 🔑 Installed Ground Station Public Key.")

        # Peer drone announcing its public key
        peer_id = data.get("drone_id")
        peer_pk_hex = data.get("public_key_hex")
        if peer_id and peer_pk_hex and peer_id != drone_id:
            peer_pk = bytes.fromhex(peer_pk_hex)
            trust_registry.register_drone(peer_id, peer_pk)
            logger.info(f"[{drone_id}] 🤝 Registered peer drone: {peer_id}")

        # Ground station assigning Shamir share for this drone
        assigned_shares = data.get("assigned_shares", {})
        if drone_id in assigned_shares:
            x, y = assigned_shares[drone_id]
            drone.share = (int(x), int(y))
            logger.info(f"[{drone_id}] 📦 Received assigned Shamir share (x={x})")

    # 2. Handle incoming GS command
    def on_command_received(topic: str, data: Dict[str, Any]):
        cmd = CommandMessage.from_dict(data)
        logger.info(f"[{drone_id}] 📩 Received mission command: {cmd.command_id}")

        is_valid, elapsed = drone.verify_gs_command(cmd)
        if not is_valid:
            logger.warning(f"[{drone_id}] ❌ Invalid GS signature on command {cmd.command_id}. Ignoring.")
            return

        logger.info(f"[{drone_id}] ✅ Verified GS Falcon signature in {elapsed*1000:.2f}ms. Broadcasting approval...")
        approval_msg, sign_time = drone.create_approval(cmd.command_id)

        # Broadcast approval to peer drones
        transport.publish(TOPIC_APPROVALS, approval_msg.to_dict())

    # 3. Handle peer approvals
    def on_peer_approval_received(topic: str, data: Dict[str, Any]):
        app = ApprovalMessage.from_dict(data)
        if app.drone_id == drone_id:
            return  # Skip own approval

        logger.info(f"[{drone_id}] 📬 Received peer approval from {app.drone_id} for command {app.command_id}")
        valid, elapsed = drone.process_peer_approval(app)
        if valid:
            current_approvals = len(drone.peer_approvals.get(app.command_id, set()))
            logger.info(f"[{drone_id}] Verified approval from {app.drone_id} in {elapsed*1000:.2f}ms. (Total: {current_approvals}/{threshold})")

            # If threshold k met for approvals, share secret share with swarm
            if current_approvals >= threshold:
                logger.info(f"[{drone_id}] 🎯 Threshold {threshold} met for approvals! Broadcasting Shamir share...")
                share_msg = drone.provide_share(app.command_id)
                transport.publish(TOPIC_SHARES, share_msg.to_dict())

    # 4. Handle peer shares & local execution
    def on_peer_share_received(topic: str, data: Dict[str, Any]):
        share_msg = ShareMessage.from_dict(data)
        if share_msg.drone_id == drone_id:
            return  # Skip own share

        stored = drone.receive_share(share_msg)
        if stored:
            logger.info(f"[{drone_id}] 📥 Verified & accepted Shamir share from {share_msg.drone_id}")

        # Check if local execution threshold is satisfied
        if drone.can_execute(share_msg.command_id):
            logger.info(f"[{drone_id}] ⚡ All threshold conditions satisfied! Reconstructing key and executing payload locally...")
            payload = drone.execute_command(share_msg.command_id)
            if payload:
                logger.info(f"[{drone_id}] 🏆 SUCCESS: Executed mission payload: {payload}")
                # Publish telemetry acknowledgment
                transport.publish(TOPIC_TELEMETRY, {
                    "drone_id": drone_id,
                    "command_id": share_msg.command_id,
                    "status": "EXECUTED",
                    "timestamp": time.time(),
                })

    # Register callbacks
    transport.register_handler(TOPIC_REGISTRY, on_registry_received)
    transport.register_handler(TOPIC_COMMANDS, on_command_received)
    transport.register_handler(TOPIC_APPROVALS, on_peer_approval_received)
    transport.register_handler(TOPIC_SHARES, on_peer_share_received)

    transport.connect()

    # Announce public key to registry
    time.sleep(1.5)
    transport.publish(TOPIC_REGISTRY, {
        "drone_id": drone_id,
        "public_key_hex": drone.public_key.hex(),
    })
    logger.info(f"[{drone_id}] 📢 Broadcasted public key to {TOPIC_REGISTRY}")

    logger.info(f"[{drone_id}] Daemon active and listening for swarm events...")

    # Main loop
    while running:
        time.sleep(1)

    transport.disconnect()
    logger.info(f"[{drone_id}] Daemon stopped.")


if __name__ == "__main__":
    main()
