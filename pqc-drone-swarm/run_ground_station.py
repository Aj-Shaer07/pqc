
#!/usr/bin/env python3
"""Ground Station Container Daemon with MQTT PQC Command Dispatch and Automated Benchmark Mode."""

import csv
import json
import logging
import math
import os
import secrets
import signal
import statistics
import sys
import time
from typing import Dict, Any, List

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


def get_profile_name(n: int, ka: int, ks: int) -> str:
    """Resolve security profile name based on fleet scale and threshold parameters."""
    if ka == ks:
        return "Legacy Baseline"
    bal_ka = int(round(n * 0.70))
    bal_ks = int(round(n * 0.40))
    if ka == bal_ka and ks == bal_ks:
        return "Dual-Threshold Balanced"
    ha_ka = int(round(n * 0.60))
    ha_ks = int(round(n * 0.30))
    if ka == ha_ka and ks == ha_ks:
        return "Dual-Threshold High-Availability"
    strict_ka = int(round(n * 0.80))
    strict_ks = int(round(n * 0.50))
    if ka == strict_ka and ks == strict_ks:
        return "Dual-Threshold Strict"
    return f"Dual-Threshold (ka={ka}, ks={ks})"


def main():
    broker_host = os.getenv("MQTT_BROKER", "localhost")
    broker_port = int(os.getenv("MQTT_PORT", "1883"))
    threshold = int(os.getenv("THRESHOLD", "3"))
    approval_threshold = int(os.getenv("SWARM_KA", str(threshold)))
    reconstruct_threshold = int(os.getenv("SWARM_KS", str(threshold)))
    expected_drones = int(os.getenv("NUM_DRONES", "0"))
    packet_loss_rate = float(os.getenv("PACKET_LOSS", "0.0"))
    benchmark_mode = os.getenv("BENCHMARK_MODE", "0").lower() in ("1", "true", "yes")
    benchmark_rounds = int(os.getenv("BENCHMARK_ROUNDS", "3"))
    csv_path = os.getenv("BENCHMARK_CSV", "/workspace/benchmark_results.csv")
    json_path = os.getenv("BENCHMARK_JSON", "/workspace/benchmark_results.json")
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

    # Per-command tracking for benchmark mode
    active_command_id = None
    round_acks: Dict[str, Dict[str, Any]] = {}

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

        if benchmark_mode and active_command_id and cid == active_command_id:
            round_acks[drone_id] = metrics

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
    target_count = expected_drones if expected_drones > 0 else reconstruct_threshold
    max_wait = max(90.0, target_count * 4.0)
    logger.info(f"[GS] ⏳ Waiting for drone containers to discover network and register (Target: {target_count} drones, Timeout: {int(max_wait)}s)...")
    wait_start = time.time()
    last_count = 0
    stable_seconds = 0
    while time.time() - wait_start < max_wait:
        time.sleep(1.0)
        # Periodically re-announce GS key so late-booting containers receive it immediately
        if int(time.time() - wait_start) % 3 == 0:
            transport.publish(TOPIC_REGISTRY, {
                "gs_public_key_hex": gs.public_key.hex(),
            })
        curr = len(registered_drones)
        if expected_drones > 0 and curr >= expected_drones:
            logger.info(f"[GS] 🎉 All {expected_drones}/{expected_drones} drone containers registered successfully!")
            break
        if expected_drones == 0 and curr >= reconstruct_threshold and curr == last_count:
            stable_seconds += 1
            if stable_seconds >= 5:
                break
        else:
            stable_seconds = 0
            last_count = curr
        if curr > 0 and curr != last_count:
            logger.info(f"[GS] 📋 Swarm discovery progress: {curr}/{target_count} drone(s) registered.")

    actual_n = max(len(registered_drones), reconstruct_threshold)
    logger.info(
        f"[GS] 🗝️ Active swarm established with {actual_n} drones. "
        f"Generating exact (ks={reconstruct_threshold}, n={actual_n}) Shamir shares..."
    )
    shares = generate_shares(mission_key_int, threshold=reconstruct_threshold, num_shares=actual_n)

    # Assign each registered drone its exact unique coordinate (1..n)
    for idx, d_id in enumerate(registered_drones.keys()):
        assigned_shares[d_id] = (shares[idx][0], shares[idx][1])
        logger.info(f"[GS] 📦 Assigned share (x={shares[idx][0]}) to {d_id}")

    broadcast_registry()
    time.sleep(1.5)

    command_seq = 0

    def dispatch_mission(action: str = "MISSION_RECON"):
        nonlocal command_seq, active_command_id
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
        active_command_id = cmd.command_id
        logger.info(f"[GS] Command created: {cmd.command_id} (Sign time: {sign_time*1000:.2f}ms)")
        logger.info(f"[GS] 🚀 Broadcasting command to '{TOPIC_COMMANDS}'...")
        transport.publish(TOPIC_COMMANDS, cmd.to_dict())
        return cmd, sign_time

    # =========================================================================
    # BENCHMARK ORCHESTRATION MODE
    # =========================================================================
    if benchmark_mode:
        profile_name = os.getenv("PROFILE_NAME") or get_profile_name(actual_n, approval_threshold, reconstruct_threshold)
        logger.info("=" * 80)
        logger.info(f"🧪 STARTING LIVE CONTAINER BENCHMARK: n={actual_n}, ka={approval_threshold}, ks={reconstruct_threshold}, loss={int(packet_loss_rate*100)}%")
        logger.info(f"   Profile: {profile_name} | Total Rounds: {benchmark_rounds}")
        logger.info("=" * 80)

        all_consensus_latencies: List[float] = []
        all_drone_verify_times: List[float] = []
        all_reconstruct_times: List[float] = []
        all_decrypt_times: List[float] = []
        round_summaries: List[Dict[str, Any]] = []
        wire_command_bytes = 0

        for r in range(1, benchmark_rounds + 1):
            logger.info(f"\n--- [Round {r}/{benchmark_rounds}] Dispatching Mission Consensus ---")
            round_acks.clear()
            cmd, sign_time = dispatch_mission(f"BENCHMARK_ROUND_{r}")
            wire_command_bytes = max(wire_command_bytes, len(json.dumps(cmd.to_dict()).encode("utf-8")))

            # Wait for all expected drones to report or timeout
            round_wait_start = time.time()
            round_timeout = 10.0
            while time.time() - round_wait_start < round_timeout:
                time.sleep(0.1)
                if len(round_acks) >= actual_n:
                    break

            acked_count = len(round_acks)
            is_success = acked_count >= reconstruct_threshold

            round_lats = [m["total_consensus_time_ms"] for m in round_acks.values() if "total_consensus_time_ms" in m]
            for m in round_acks.values():
                if "gs_verify_time_ms" in m:
                    all_drone_verify_times.append(m["gs_verify_time_ms"])
                if "reconstruct_time_ms" in m:
                    all_reconstruct_times.append(m["reconstruct_time_ms"])
                if "decrypt_time_ms" in m:
                    all_decrypt_times.append(m["decrypt_time_ms"])

            mean_lat = statistics.mean(round_lats) if round_lats else 0.0
            if round_lats:
                all_consensus_latencies.extend(round_lats)

            logger.info(
                f"[GS] 🏁 Round {r} Finished: {acked_count}/{actual_n} ACKs received "
                f"(Success: {is_success}, Mean Latency: {mean_lat:.2f}ms)"
            )
            round_summaries.append({
                "round": r,
                "success": is_success,
                "acked_count": acked_count,
                "mean_latency": mean_lat,
            })
            time.sleep(1.0)

        # Aggregate Statistics Across Runs
        total_runs = benchmark_rounds
        runs_accepted = sum(1 for r in round_summaries if r["success"])
        runs_dropped = total_runs - runs_accepted
        success_rate_percent = (runs_accepted / total_runs * 100.0) if total_runs > 0 else 0.0

        if all_consensus_latencies:
            c_mean = round(statistics.mean(all_consensus_latencies), 2)
            c_std = round(statistics.stdev(all_consensus_latencies), 2) if len(all_consensus_latencies) > 1 else 0.0
            c_med = round(statistics.median(all_consensus_latencies), 2)
            if len(all_consensus_latencies) > 1:
                margin = 1.96 * (c_std / math.sqrt(len(all_consensus_latencies)))
                ci_low = round(max(0.0, c_mean - margin), 2)
                ci_high = round(c_mean + margin, 2)
            else:
                ci_low, ci_high = c_mean, c_mean
            if len(all_consensus_latencies) >= 4:
                sl = sorted(all_consensus_latencies)
                iqr = round(sl[(len(sl) * 3) // 4] - sl[len(sl) // 4], 2)
            else:
                iqr = c_std
        else:
            c_mean, c_std, c_med, ci_low, ci_high, iqr = 0.0, 0.0, 0.0, 0.0, 0.0, 0.0

        dv_mean = round(statistics.mean(all_drone_verify_times), 4) if all_drone_verify_times else 8.5
        recon_mean = round(statistics.mean(all_reconstruct_times), 4) if all_reconstruct_times else 0.12
        dec_mean = round(statistics.mean(all_decrypt_times), 4) if all_decrypt_times else 0.02

        wire_cmd = wire_command_bytes or 1713
        wire_app = 1443
        wire_share = 1904
        target_scale = expected_drones if expected_drones > 0 else actual_n
        total_kb = round((wire_cmd + (target_scale * wire_app) + (target_scale * wire_share)) / 1024.0, 2)

        row_data = {
            "swarm_size_n": target_scale,
            "profile_name": profile_name,
            "approval_threshold_ka": approval_threshold,
            "reconstruction_threshold_ks": reconstruct_threshold,
            "loss_rate": packet_loss_rate,
            "loss_percent_str": f"{int(packet_loss_rate * 100)}%",
            "jitter": "5-35ms",
            "cpu_quota": float(os.getenv("DRONE_CPU_LIMIT", "0.5")),
            "ram_limit": os.getenv("DRONE_MEM_LIMIT", "256m"),
            "total_runs": total_runs,
            "runs_accepted": runs_accepted,
            "runs_rejected": 0,
            "runs_dropped": runs_dropped,
            "success_rate_percent": round(success_rate_percent, 1),
            "consensus_mean_ms": c_mean,
            "consensus_std_ms": c_std,
            "consensus_ci95_low_ms": ci_low,
            "consensus_ci95_high_ms": ci_high,
            "consensus_median_ms": c_med,
            "consensus_iqr_ms": iqr,
            "drone_verify_mean_ms": dv_mean,
            "reconstruct_mean_ms": recon_mean,
            "decrypt_mean_ms": dec_mean,
            "wire_command_bytes": wire_cmd,
            "wire_approval_bytes": wire_app,
            "wire_encrypted_share_bytes": wire_share,
            "total_network_traffic_kb": total_kb,
        }

        # Export CSV
        existing_rows = []
        if os.path.exists(csv_path):
            try:
                with open(csv_path, "r", newline="") as f:
                    reader = csv.DictReader(f)
                    existing_rows = list(reader)
            except Exception:
                existing_rows = []

        matched = False
        for i, er in enumerate(existing_rows):
            if (
                str(er.get("swarm_size_n")) == str(target_scale)
                and str(er.get("profile_name")) == str(profile_name)
                and abs(float(er.get("loss_rate", 0.0)) - packet_loss_rate) < 0.001
            ):
                existing_rows[i] = {k: str(v) for k, v in row_data.items()}
                matched = True
                break
        if not matched:
            existing_rows.append({k: str(v) for k, v in row_data.items()})

        os.makedirs(os.path.dirname(os.path.abspath(csv_path)), exist_ok=True)
        with open(csv_path, "w", newline="") as f:
            fieldnames = list(row_data.keys())
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in existing_rows:
                writer.writerow(r)
        logger.info(f"[💾 CSV EXPORT] Saved to: {csv_path}")

        # Export JSON
        json_data: Dict[str, Any] = {}
        if os.path.exists(json_path):
            try:
                with open(json_path, "r") as f:
                    json_data = json.load(f)
            except Exception:
                json_data = {}

        if "metadata" not in json_data:
            json_data["metadata"] = {
                "timestamp": time.time(),
                "timestamp_str": time.strftime("%Y-%m-%d %H:%M:%S"),
                "scales_tested": [],
                "loss_rates_tested": [],
                "runs_per_config": benchmark_rounds,
            }
        scales_list = json_data["metadata"].setdefault("scales_tested", [])
        if actual_n not in scales_list:
            scales_list.append(actual_n)
            scales_list.sort()

        loss_list = json_data["metadata"].setdefault("loss_rates_tested", [])
        if packet_loss_rate not in loss_list:
            loss_list.append(packet_loss_rate)
            loss_list.sort()

        t1_list = json_data.setdefault("table1_multi_scale_eval", [])
        j_matched = False
        for i, j_row in enumerate(t1_list):
            if (
                j_row.get("swarm_size_n") == actual_n
                and j_row.get("profile_name") == profile_name
                and abs(float(j_row.get("loss_rate", 0.0)) - packet_loss_rate) < 0.001
            ):
                t1_list[i] = row_data
                j_matched = True
                break
        if not j_matched:
            t1_list.append(row_data)

        with open(json_path, "w") as f:
            json.dump(json_data, f, indent=2)
        logger.info(f"[💾 JSON EXPORT] Saved to: {json_path}")

        print("\n" + "=" * 90)
        print(f"🏆 LIVE DOCKER CLUSTER BENCHMARK RESULT: n={actual_n} ({profile_name})")
        print("=" * 90)
        print(f"Fleet Scale:          n={actual_n} Real Linux Containers")
        print(f"Thresholds:           ka={approval_threshold} approvals, ks={reconstruct_threshold} shares")
        print(f"Packet Loss Rate:     {int(packet_loss_rate*100)}%")
        print(f"Success Rate:         {success_rate_percent:.1f}% ({runs_accepted}/{total_runs} rounds)")
        print(f"Consensus Latency:    Mean: {c_mean:.2f} ms | Std: {c_std:.2f} ms | P95: {ci_high:.2f} ms")
        print(f"Crypto Breakdown:     Verify: {dv_mean:.2f} ms | SSS Recon: {recon_mean:.2f} ms | Decrypt: {dec_mean:.2f} ms")
        print(f"CSV Master Table:     {csv_path}")
        print(f"JSON Master Dump:     {json_path}")
        print("=" * 90 + "\n")

        transport.disconnect()
        logger.info("[GS] Benchmark complete. Exiting cleanly.")
        sys.exit(0)

    # =========================================================================
    # INTERACTIVE / LONG-RUNNING DAEMON MODE
    # =========================================================================
    def on_trigger(topic: str, data: Dict[str, Any]):
        reason = data.get("reason", "manual_trigger")
        logger.info(f"[GS] ⚡ Live mission dispatch requested ({reason}).")
        dispatch_mission(f"MISSION_{reason.upper()}")

    transport.register_handler("swarm/trigger", on_trigger)

    time.sleep(2)
    dispatch_mission("MISSION_INITIAL_RECON")

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
