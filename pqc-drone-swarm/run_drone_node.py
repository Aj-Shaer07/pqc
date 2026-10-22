#!/usr/bin/env python3
"""Autonomous Drone Container Daemon with MQTT P2P Gossip."""

import logging
import os
import secrets
import signal
import sys
import threading
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
    approval_threshold = int(os.getenv("SWARM_KA", os.getenv("THRESHOLD", "3")))
    reconstruct_threshold = int(os.getenv("SWARM_KS", os.getenv("THRESHOLD", "3")))
    packet_loss_rate = float(os.getenv("PACKET_LOSS", "0.0"))

    # Extract unique Drone ID from container hostname or env
    hostname = os.getenv("HOSTNAME", "node")[:8]
    drone_id = os.getenv("DRONE_ID", f"DRONE_{hostname}")

    loss_str = f" | Loss: {int(packet_loss_rate*100)}%" if packet_loss_rate > 0.0 else ""
    logger.info(f"🚀 Initializing Autonomous Drone Node: {drone_id} (ka={approval_threshold}, ks={reconstruct_threshold}{loss_str})")

    trust_registry = TrustRegistry()
    
    mesh_key_hex = os.getenv("SWARM_MESH_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    mesh_key = bytes.fromhex(mesh_key_hex) if mesh_key_hex else None
    if mesh_key:
        logger.info(f"[{drone_id}] 🔐 Swarm Broadcast Mesh Key configured (Wire Confidentiality active).")

    freshness_window = float(os.getenv("FRESHNESS_WINDOW", "30.0"))
    share_assigned = threading.Event()

    # Initialize Drone with dummy share initially; real share provided via GS registry or derived
    # We assign dynamic share index based on hash or container instance
    node_index = abs(hash(drone_id)) % 1000 + 1
    # Temporary placeholder share until GS onboard handshake
    drone = DroneNode(
        drone_id=drone_id,
        share=(node_index, 0),
        threshold=reconstruct_threshold,
        approval_threshold=approval_threshold,
        reconstruct_threshold=reconstruct_threshold,
        trust_registry=trust_registry,
        mesh_key=mesh_key,
        freshness_window_sec=freshness_window,
    )

    transport = SwarmMQTTTransport(
        client_id=f"{drone_id}_{secrets.token_hex(4)}",
        broker_host=broker_host,
        broker_port=broker_port,
    )

    # 1. Handle Registry: GS public key, peer public keys, cluster peer registry, and assigned shares
    def on_registry_received(topic: str, data: Dict[str, Any]):
        # Ground Station announcing its public key
        if "gs_public_key_hex" in data:
            gs_pk = bytes.fromhex(data["gs_public_key_hex"])
            trust_registry.set_gs_public_key(gs_pk)
            logger.info(f"[{drone_id}] 🔑 Installed Ground Station Public Key.")

        # Synchronize full cluster peer registry broadcasted by Ground Station
        if "peer_registry" in data:
            synced_count = 0
            for peer_id, peer_pk_hex in data["peer_registry"].items():
                if peer_id != drone_id:
                    try:
                        peer_pk = bytes.fromhex(peer_pk_hex)
                        trust_registry.register_drone(peer_id, peer_pk)
                        synced_count += 1
                    except Exception:
                        pass
            if synced_count > 0:
                logger.info(f"[{drone_id}] 🤝 Synchronized {synced_count} peer drone(s) from cluster registry.")

        # Peer drone announcing its public key directly
        peer_id = data.get("drone_id")
        peer_pk_hex = data.get("public_key_hex")
        if peer_id and peer_pk_hex and peer_id != drone_id:
            try:
                peer_pk = bytes.fromhex(peer_pk_hex)
                trust_registry.register_drone(peer_id, peer_pk)
                logger.info(f"[{drone_id}] 🤝 Registered peer drone: {peer_id}")
            except Exception:
                pass

        # Ground station assigning Shamir share for this drone
        assigned_shares = data.get("assigned_shares", {})
        if drone_id in assigned_shares:
            x, y = assigned_shares[drone_id]
            drone.share = (int(x), int(y))
            share_assigned.set()
            logger.info(f"[{drone_id}] 📦 Received assigned Shamir share (x={x})")

    # 2. Handle incoming GS command
    def on_command_received(topic: str, data: Dict[str, Any]):
        try:
            cmd = CommandMessage.from_dict(data)
        except Exception as e:
            logger.warning(f"[{drone_id}] 🛡️ Malformed mission command rejected ({type(e).__name__}: {e})")
            transport.publish(TOPIC_TELEMETRY, {
                "drone_id": drone_id,
                "event": "SECURITY_ALERT",
                "alert_type": "MALFORMED_COMMAND",
                "reason": str(e),
                "timestamp": time.time(),
            })
            return

        logger.info(f"[{drone_id}] 📩 Received mission command: {cmd.command_id}")

        if packet_loss_rate > 0.0 and (secrets.randbelow(10000) / 10000.0) < packet_loss_rate:
            logger.info(f"[{drone_id}] 📭 Dropped mission command {cmd.command_id} (simulated RF packet loss: {int(packet_loss_rate*100)}%)")
            return

        is_valid, elapsed = drone.verify_gs_command(cmd)
        if not is_valid:
            reason = drone.last_rejection_reason or "Verification failed"
            logger.warning(f"[{drone_id}] ❌ Command {cmd.command_id} rejected ({reason}). Ignoring.")
            transport.publish(TOPIC_TELEMETRY, {
                "drone_id": drone_id,
                "event": "SECURITY_ALERT",
                "alert_type": "COMMAND_REJECTED",
                "reason": reason,
                "command_id": cmd.command_id,
                "timestamp": time.time(),
            })
            return

        logger.info(f"[{drone_id}] ✅ Verified GS Falcon signature in {elapsed*1000:.2f}ms. Broadcasting approval...")
        approval_msg, sign_time = drone.create_approval(cmd.command_id)

        # Broadcast approval to peer drones
        transport.publish(TOPIC_APPROVALS, approval_msg.to_dict())

    broadcasted_shares = set()
    executed_commands = set()

    # 3. Handle peer approvals
    def on_peer_approval_received(topic: str, data: Dict[str, Any]):
        try:
            app = ApprovalMessage.from_dict(data)
        except Exception as e:
            logger.warning(f"[{drone_id}] 🛡️ Malformed peer approval rejected ({type(e).__name__}: {e})")
            transport.publish(TOPIC_TELEMETRY, {
                "drone_id": drone_id,
                "event": "SECURITY_ALERT",
                "alert_type": "MALFORMED_APPROVAL",
                "reason": str(e),
                "timestamp": time.time(),
            })
            return

        if app.drone_id == drone_id:
            return  # Skip own approval

        if packet_loss_rate > 0.0 and (secrets.randbelow(10000) / 10000.0) < packet_loss_rate:
            return

        logger.info(f"[{drone_id}] 📬 Received peer approval from {app.drone_id} for command {app.command_id}")
        valid, elapsed = drone.process_peer_approval(app)
        if valid:
            current_approvals = len(drone.peer_approvals.get(app.command_id, set()))
            logger.info(f"[{drone_id}] Verified approval from {app.drone_id} in {elapsed*1000:.2f}ms. (Total: {current_approvals}/{drone.approval_threshold})")

            # If approval threshold ka met, broadcast Shamir share once
            if drone.can_release_share(app.command_id) and app.command_id not in broadcasted_shares:
                broadcasted_shares.add(app.command_id)
                logger.info(f"[{drone_id}] 🎯 Approval threshold ka={drone.approval_threshold} met! Broadcasting Shamir share...")
                share_msg = drone.provide_share(app.command_id)
                transport.publish(TOPIC_SHARES, share_msg.to_dict())
        else:
            reason = drone.last_rejection_reason or "Invalid peer approval"
            logger.warning(f"[{drone_id}] ⚠️ Peer approval from {app.drone_id} rejected: {reason}")
            transport.publish(TOPIC_TELEMETRY, {
                "drone_id": drone_id,
                "event": "SECURITY_ALERT",
                "alert_type": "APPROVAL_REJECTED",
                "reason": reason,
                "source_peer": app.drone_id,
                "command_id": app.command_id,
                "timestamp": time.time(),
            })

    # 4. Handle peer shares & local execution
    def on_peer_share_received(topic: str, data: Dict[str, Any]):
        try:
            share_msg = ShareMessage.from_dict(data)
        except Exception as e:
            logger.warning(f"[{drone_id}] 🛡️ Malformed peer share rejected ({type(e).__name__}: {e})")
            transport.publish(TOPIC_TELEMETRY, {
                "drone_id": drone_id,
                "event": "SECURITY_ALERT",
                "alert_type": "MALFORMED_SHARE",
                "reason": str(e),
                "timestamp": time.time(),
            })
            return

        if share_msg.drone_id == drone_id:
            return

        if packet_loss_rate > 0.0 and (secrets.randbelow(10000) / 10000.0) < packet_loss_rate:
            return

        stored = drone.receive_share(share_msg)
        if stored:
            enc_tag = "🔒 AEAD Encrypted" if share_msg.is_encrypted else "Plaintext"
            logger.info(f"[{drone_id}] 📥 Verified & accepted Shamir share from {share_msg.drone_id} ({enc_tag})")
        else:
            reason = drone.last_rejection_reason or "Verification failed"
            logger.warning(f"[{drone_id}] ❌ Rejected share from {share_msg.drone_id}: {reason}")
            transport.publish(TOPIC_TELEMETRY, {
                "drone_id": drone_id,
                "event": "SECURITY_ALERT",
                "alert_type": "SHARE_REJECTED",
                "reason": reason,
                "source_peer": share_msg.drone_id,
                "command_id": share_msg.command_id,
                "timestamp": time.time(),
            })

        # Check if local execution threshold is satisfied
        if share_msg.command_id not in executed_commands and drone.can_execute(share_msg.command_id):
            executed_commands.add(share_msg.command_id)
            logger.info(f"[{drone_id}] ⚡ All threshold conditions satisfied! Reconstructing key and executing payload locally...")
            payload = drone.execute_command(share_msg.command_id)
            if payload:
                logger.info(f"[{drone_id}] 🏆 SUCCESS: Executed mission payload: {payload}")
                metrics = drone.get_metrics(share_msg.command_id) or {}
                # Publish telemetry acknowledgment with performance metrics
                transport.publish(TOPIC_TELEMETRY, {
                    "drone_id": drone_id,
                    "command_id": share_msg.command_id,
                    "status": "EXECUTED",
                    "timestamp": time.time(),
                    "metrics": metrics,
                })

    # Register callbacks
    transport.register_handler(TOPIC_REGISTRY, on_registry_received)
    transport.register_handler(TOPIC_COMMANDS, on_command_received)
    transport.register_handler(TOPIC_APPROVALS, on_peer_approval_received)
    transport.register_handler(TOPIC_SHARES, on_peer_share_received)

    transport.connect()

    # Announce public key to registry periodically until assigned share is confirmed by Ground Station
    logger.info(f"[{drone_id}] 📢 Announcing public key to {TOPIC_REGISTRY} until registered...")
    announce_start = time.time()
    while running and not share_assigned.is_set() and (time.time() - announce_start < 180.0):
        transport.publish(TOPIC_REGISTRY, {
            "drone_id": drone_id,
            "public_key_hex": drone.public_key.hex(),
        })
        share_assigned.wait(timeout=2.0)
    logger.info(f"[{drone_id}] 🤝 Handshake confirmed by Ground Station on {TOPIC_REGISTRY}")

    logger.info(f"[{drone_id}] Daemon active and listening for swarm events...")

    # Main loop
    while running:
        time.sleep(1)

    transport.disconnect()
    logger.info(f"[{drone_id}] Daemon stopped.")


if __name__ == "__main__":
    main()
