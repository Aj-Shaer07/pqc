#!/usr/bin/env python3
"""Simulation and benchmarking runner across all swarm configurations (k, n)."""

import argparse
import csv
import json
import os
import sys
import time

# Auto-resolve paths
script_dir = os.path.dirname(os.path.abspath(__file__))
implementation_root = os.path.abspath(os.path.join(script_dir, ".."))
src_path = os.path.join(script_dir, "src")
falcon_path = os.getenv("FALCON_PATH") or os.path.join(implementation_root, "falcon_py")

for p in [src_path, falcon_path]:
    if p not in sys.path and os.path.isdir(p):
        sys.path.insert(0, p)

from pqc_swarm.sim.in_memory_sim import run_decentralized_simulation


DEFAULT_CONFIGURATIONS = [
    (3, 5),
    (5, 10),
    (10, 20),
    (25, 50),
]


def mean(val_list):
    return sum(val_list) / len(val_list) if val_list else 0.0


def run_benchmark(configurations, num_runs=10, output_csv=None):
    all_summary = []

    print("\n" + "=" * 70)
    print(f"🚀 PQC DECENTRALIZED SWARM BENCHMARK SUITE")
    print(f"   Configs to test: {configurations}")
    print(f"   Iterations per config: {num_runs}")
    print("=" * 70 + "\n")

    for k, n in configurations:
        print(f"\n{'*' * 50}")
        print(f"🔄 Starting Configuration: Threshold k={k}, Swarm Size n={n} ({num_runs} runs)")
        print(f"{'*' * 50}")

        metrics = {
            "gs_keygen": [],
            "gs_sign": [],
            "drone_keygen_avg": [],
            "drone_verify_avg": [],
            "drone_approve_avg": [],
            "peer_verify_avg": [],
            "round_duration": [],
        }

        successful_runs = 0

        for r in range(1, num_runs + 1):
            print(f"  [Run {r:02d}/{num_runs:02d}] Executing simulation...", end="", flush=True)
            start_round = time.perf_counter()
            try:
                res = run_decentralized_simulation(k=k, n=n)
                round_time = time.perf_counter() - start_round

                metrics["gs_keygen"].append(res["gs_keygen"])
                metrics["gs_sign"].append(res["gs_sign"])
                metrics["drone_keygen_avg"].append(res["drone_keygen_avg"])
                metrics["drone_verify_avg"].append(res["drone_verify_avg"])
                metrics["drone_approve_avg"].append(res["drone_approve_avg"])
                metrics["peer_verify_avg"].append(res["peer_verify_avg"])
                metrics["round_duration"].append(round_time)

                successful_runs += 1
                print(f" ✅ Success ({round_time:.2f}s) | Executed: {res['executed_count']}/{n}")
            except Exception as e:
                print(f" ❌ Failed: {e}")

        if not metrics["gs_keygen"]:
            print(f"[!] Warning: No successful runs for k={k}, n={n}")
            continue

        summary_row = {
            "k": k,
            "n": n,
            "runs": successful_runs,
            "round_duration_mean": round(mean(metrics["round_duration"]), 4),
            "gs_keygen_mean": round(mean(metrics["gs_keygen"]), 6),
            "gs_sign_mean": round(mean(metrics["gs_sign"]), 6),
            "drone_keygen_mean": round(mean(metrics["drone_keygen_avg"]), 6),
            "drone_verify_mean": round(mean(metrics["drone_verify_avg"]), 6),
            "drone_approve_mean": round(mean(metrics["drone_approve_avg"]), 6),
            "peer_verify_mean": round(mean(metrics["peer_verify_avg"]), 6),
        }
        all_summary.append(summary_row)

        print(f"\n  📊 Summary for (k={k}, n={n}):")
        print(f"     - Mean Round Duration:  {summary_row['round_duration_mean']:.3f} s")
        print(f"     - GS Sign Time:         {summary_row['gs_sign_mean']*1000:.2f} ms")
        print(f"     - Drone Verify GS Time: {summary_row['drone_verify_mean']*1000:.2f} ms")
        print(f"     - Drone Approve Time:   {summary_row['drone_approve_mean']*1000:.2f} ms")
        print(f"     - Peer Verify Time:     {summary_row['peer_verify_mean']*1000:.2f} ms")

    if output_csv and all_summary:
        with open(output_csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=all_summary[0].keys())
            writer.writeheader()
            for row in all_summary:
                writer.writerow(row)
        print(f"\n[💾 SUCCESS] Saved benchmark results to: {output_csv}")

    return all_summary


def main():
    parser = argparse.ArgumentParser(
        description="Run Decentralized PQC Drone Swarm Simulation & Benchmarks"
    )
    parser.add_argument(
        "--all-configs",
        action="store_true",
        default=True,
        help="Run benchmark over all standard configurations: (3,5), (5,10), (10,20), (25,50) (default: True)",
    )
    parser.add_argument(
        "--single",
        action="store_true",
        help="Run only a single custom configuration specified by -k and -n",
    )
    parser.add_argument("-k", "--threshold", type=int, default=3, help="Custom threshold (used with --single)")
    parser.add_argument("-n", "--nodes", type=int, default=5, help="Custom node count (used with --single)")
    parser.add_argument(
        "-r", "--runs", type=int, default=10, help="Number of benchmark iterations per config (default: 10)"
    )
    parser.add_argument(
        "--csv",
        type=str,
        default=os.path.join(script_dir, "multi_simulation_results.csv"),
        help="Path to export CSV results (default: multi_simulation_results.csv)",
    )

    args = parser.parse_args()

    if args.single:
        configs = [(args.threshold, args.nodes)]
    else:
        configs = DEFAULT_CONFIGURATIONS

    run_benchmark(configs, num_runs=args.runs, output_csv=args.csv)


if __name__ == "__main__":
    main()
