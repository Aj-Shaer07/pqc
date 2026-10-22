#!/usr/bin/env bash
# ==============================================================================
# PQC Drone Swarm - Interactive Docker Management Script
# ==============================================================================

set -e

# Default parameters
DEFAULT_DRONES=5
DEFAULT_MEMORY="256m"   # Simulating lightweight companion computers (e.g. Raspberry Pi Zero 2W / CM4)
DEFAULT_CPUS="0.5"

# Print menu if no arguments provided
show_help() {
    echo ""
    echo "================================================================="
    echo "🚁 PQC Drone Swarm - Docker Controller"
    echo "================================================================="
    echo "Usage: ./docker_commands.sh [command] [options]"
    echo ""
    echo "Commands:"
    echo "  simulate [N] [KA] [KS] [LOSS] [RUNS] [MEM] [CPUS]"
    echo "                         Run complete Phase 3.2 simulation (Table 1 multi-scale sweep across 4 profiles"
    echo "                         and 5 loss rates, Table 2 hardware constraint tiers, Table 3 Red-Team attacks)."
    echo "                         Auto-exports complete benchmark_results.csv and benchmark_results.json."
    echo "  cluster-sweep [SCALES] [KA] [KS] [LOSS] [RUNS] [MEM] [CPUS]"
    echo "                         Run live multi-container cluster benchmark across scales (default: 10 20 30 40 50)."
    echo "                         Starts N real drone containers, measures MQTT consensus latency, auto-exports"
    echo "                         directly to benchmark_results.csv & benchmark_results.json, and tears down per scale."
    echo "  build                  Build the base Debian-slim Docker image"
    echo "  test                   Run unit tests inside an isolated container"
    echo "  sim-single             Run single benchmark inside container (k=3, n=5)"
    echo "  sim-all                Run full paper benchmarks (all configs, k/n)"
    echo "  up [N] [MEM] [CPUS]    Start multi-container swarm with N drones"
    echo "                         (Defaults: N=$DEFAULT_DRONES, MEM=$DEFAULT_MEMORY, CPUS=$DEFAULT_CPUS)"
    echo "  attack [demo|eavesdrop|tamper|wrong-key|replay|rogue-gs|geofence|multi-sig] [DUR] [TARGET]"
    echo "                         Run Red-Team attack battery against the swarm (defaults: demo)"
    echo "  down                   Stop and remove all swarm containers & network"
    echo "  logs                   Follow real-time logs from all swarm nodes"
    echo "  plot                   Generate all publication-quality comparison and safety defense plots"
    echo ""
    echo "Examples:"
    echo "  ./docker_commands.sh simulate            # Full evaluation matrix (Tables 1, 2, 3, all profiles & loss)"
    echo "  ./docker_commands.sh simulate --quick    # Quick 1-round smoke test across all configurations"
    echo "  ./docker_commands.sh simulate 10 7 4     # Custom single config: n=10, ka=7, ks=4"
    echo "  ./docker_commands.sh cluster-sweep       # Live container sweep across n=10,20,30,40,50 with teardown"
    echo "  ./docker_commands.sh cluster-sweep 10    # Live container benchmark for n=10"
    echo "  ./docker_commands.sh build"
    echo "  ./docker_commands.sh test"
    echo "  ./docker_commands.sh plot                # Generate all 19 publication-quality plots in paper/result/"
    echo "  ./docker_commands.sh attack demo         # In-memory security validation battery (all 7 vectors)"
    echo "  ./docker_commands.sh attack geofence 15  # Rogue GS out-of-boundary flight command injection"
    echo "  ./docker_commands.sh attack multi-sig 15 # Multi-operator threshold authorization (1-of-2 vs 2-of-2)"
    echo "  ./docker_commands.sh attack eavesdrop 30 # Sniff MQTT traffic on running cluster"
    echo "  ./docker_commands.sh attack tamper 30 all# Active MitM ciphertext injection"
    echo "  ./docker_commands.sh attack wrong-key 30 # Rogue container with invalid key"
    echo "  ./docker_commands.sh attack replay 30    # Temporal replay of valid signed shares"
    echo "  ./docker_commands.sh attack rogue-gs 20  # Forged Ground Station command injection"
    echo "  ./docker_commands.sh up 5                # Spin up 5 drones with 256MB RAM each"
    echo "  ./docker_commands.sh down"
    echo "================================================================="
    echo ""
}

CMD=${1:-help}

case "$CMD" in
    build)
        echo "[*] Building Debian-slim base image (pqc-drone-swarm:latest)..."
        docker build -t pqc-drone-swarm:latest .
        ;;

    test)
        echo "[*] Running unit test battery inside isolated container..."
        docker run --rm -v "$PWD/pqc-drone-swarm:/app/pqc-drone-swarm" pqc-drone-swarm:latest
        ;;

    attack)
        MODE=${2:-demo}
        DUR=${3:-25}
        TARGET=${4:-all}

        # Resolve drone container aliases (e.g. DRONE_2, drone-2, 2) to container's swarm ID (DRONE_<hex>)
        if [ "$TARGET" != "all" ] && [ "$TARGET" != "any" ]; then
            NUM=$(echo "$TARGET" | grep -o -E '[0-9]+' | tail -n 1)
            if [ -n "$NUM" ] && [ "${#TARGET}" -lt 12 ]; then
                MATCHED_CID=$(docker ps --format '{{.Names}} {{.ID}}' 2>/dev/null | awk -v n="drone-$NUM" '($1 ~ ("-" n "$") || $1 ~ ("_" n "$") || $1 == n) {print $2; exit}')
                if [ -n "$MATCHED_CID" ]; then
                    RESOLVED="DRONE_${MATCHED_CID:0:8}"
                    echo "[*] Resolved target alias '$TARGET' -> Container pqc-drone-$NUM ($RESOLVED)"
                    TARGET="$RESOLVED"
                fi
            elif [[ "$TARGET" =~ ^[0-9a-fA-F]{8}$ ]]; then
                TARGET="DRONE_$TARGET"
            fi
        fi

        echo "[*] Running Red-Team adversary simulation (Mode: $MODE, Target: $TARGET)..."
        if [ "$MODE" = "demo" ]; then
            docker run --rm -v "$PWD/pqc-drone-swarm:/app/pqc-drone-swarm" pqc-drone-swarm:latest python3 simulate_adversary.py --mode demo
        else
            # Verify that the swarm cluster is actually active
            if ! docker ps --format '{{.Names}}' | grep -q 'pqc_mqtt_broker'; then
                echo ""
                echo "⚠️  [WARNING] The live swarm cluster is NOT running!"
                echo "   The attack modes (wrong-key, tamper, eavesdrop) connect to live containers on 'swarm-net'."
                echo "   To start the swarm cluster, run:"
                echo "      ./docker_commands.sh up 5"
                echo ""
                echo "   Alternatively, to run the self-contained security battery without a cluster, use:"
                echo "      ./docker_commands.sh attack demo"
                echo ""
                exit 1
            fi
            docker run --rm --network swarm-net -v "$PWD/pqc-drone-swarm:/app/pqc-drone-swarm" -e MQTT_BROKER=mqtt-broker pqc-drone-swarm:latest python3 simulate_adversary.py --mode "$MODE" --duration "$DUR" --target "$TARGET"
        fi
        ;;

    sim-single)
        echo "[*] Running single simulation benchmark (k=3, n=5)..."
        docker run --rm pqc-drone-swarm:latest python3 run_simulation.py --single -k 3 -n 5 -r 1
        ;;

    sim-all)
        RUNS=${2:-3}
        echo "[*] Running full benchmark across all configurations ($RUNS runs each)..."
        docker run --rm pqc-drone-swarm:latest python3 run_simulation.py -r "$RUNS"
        ;;

    simulate)
        # Usage: ./docker_commands.sh simulate [--live] OR [--quick] OR [N] [KA] [KS] [LOSS] [RUNS] [MEM] [CPUS]
        if [ "$2" = "--live" ] || [ "$2" = "--cluster" ]; then
            shift
            # Forward to cluster-sweep
            "$0" cluster-sweep "$@"
            exit $?
        fi

        EXTRA_ARGS=()
        SIM_MEM="2g"
        SIM_CPUS=""

        if [ "$2" = "--quick" ] || [ "$2" = "-q" ]; then
            EXTRA_ARGS+=(--quick)
            TARGET_RUNS=${3:-""}
            if [ -n "$TARGET_RUNS" ]; then
                EXTRA_ARGS+=(-r "$TARGET_RUNS")
            fi
        elif [[ "$2" == -* ]]; then
            EXTRA_ARGS=("$@")
        else
            TARGET_N=${2:-""}
            TARGET_KA=${3:-""}
            TARGET_KS=${4:-""}
            TARGET_LOSS=${5:-""}
            TARGET_RUNS=${6:-""}
            SIM_MEM=${7:-"2g"}
            SIM_CPUS=${8:-""}

            if [ -n "$TARGET_N" ] && [ -n "$TARGET_KA" ] && [ -n "$TARGET_KS" ]; then
                EXTRA_ARGS+=(--single -n "$TARGET_N" --ka "$TARGET_KA" --ks "$TARGET_KS")
            elif [ -n "$TARGET_N" ]; then
                EXTRA_ARGS+=(--scales "$TARGET_N")
            fi
            if [ -n "$TARGET_LOSS" ]; then
                EXTRA_ARGS+=(--loss "$TARGET_LOSS")
            fi
            if [ -n "$TARGET_RUNS" ]; then
                EXTRA_ARGS+=(-r "$TARGET_RUNS")
            fi
        fi

        CPU_DISPLAY=${SIM_CPUS:-"Host Multi-Core Auto"}
        CPU_ARG=()
        if [ -n "$SIM_CPUS" ]; then
            CPU_ARG+=(--cpus="$SIM_CPUS")
        fi

        echo "================================================================="
        echo "🚀 Running PQC Swarm Comprehensive Simulation (Phase 3.2)"
        echo "   Memory Limit: $SIM_MEM | CPU Quota: $CPU_DISPLAY"
        echo "   Export CSV:   $PWD/benchmark_results.csv"
        echo "   Export JSON:  $PWD/benchmark_results.json"
        echo "================================================================="

        docker run --rm \
            -v "$PWD:/workspace" \
            -v "$PWD/pqc-drone-swarm:/app/pqc-drone-swarm" \
            -w /app/pqc-drone-swarm \
            --memory="$SIM_MEM" \
            "${CPU_ARG[@]}" \
            pqc-drone-swarm:latest \
            python3 run_simulation.py \
            --csv /workspace/benchmark_results.csv \
            --json /workspace/benchmark_results.json \
            "${EXTRA_ARGS[@]}"
        ;;

    cluster-sweep)
        # Usage: ./docker_commands.sh cluster-sweep [--resume] [--quick] [--full-loss] [SCALES] [ROUNDS]
        #    OR: ./docker_commands.sh cluster-sweep [SCALE] [KA] [KS] [LOSS] [RUNS] [MEM] [CPUS]
        IS_QUICK=0
        FULL_LOSS=0
        IS_RESUME=0

        while [ "$#" -gt 1 ]; do
            case "$2" in
                --quick|-q)
                    IS_QUICK=1
                    shift
                    ;;
                --full-loss)
                    FULL_LOSS=1
                    shift
                    ;;
                --resume|-r)
                    IS_RESUME=1
                    shift
                    ;;
                *)
                    break
                    ;;
            esac
        done

        TARGET_ARG=${2:-""}
        CUSTOM_KA=""
        CUSTOM_KS=""
        CUSTOM_LOSS=""
        TARGET_RUNS="10"
        TARGET_MEM=${DEFAULT_MEMORY}
        TARGET_CPUS=${DEFAULT_CPUS}

        if [ -n "$3" ] && [ -z "$4" ]; then
            # Format: cluster-sweep [SCALES] [ROUNDS]
            TARGET_RUNS="$3"
        elif [ -n "$3" ] && [ -n "$4" ]; then
            # Format: cluster-sweep [SCALE] [KA] [KS] [LOSS] [RUNS]
            CUSTOM_KA="$3"
            CUSTOM_KS="$4"
            CUSTOM_LOSS=${5:-""}
            TARGET_RUNS=${6:-"10"}
            TARGET_MEM=${7:-$DEFAULT_MEMORY}
            TARGET_CPUS=${8:-$DEFAULT_CPUS}
        fi

        if [ "$IS_QUICK" -eq 1 ]; then
            TARGET_RUNS="1"
        fi

        if [ -z "$TARGET_ARG" ] || [ "$TARGET_ARG" = "all" ]; then
            SCALES=(10 20 30 40 50)
        else
            IFS=',' read -r -a SCALES <<< "$TARGET_ARG"
        fi

        # Loss sweep selection
        if [ -n "$CUSTOM_LOSS" ]; then
            LOSS_RATES=("$CUSTOM_LOSS")
        elif [ "$IS_QUICK" -eq 1 ]; then
            LOSS_RATES=(0.0)
        else
            # Default matches simulate default: 0%, 5%, 10%, 15%, 20%
            LOSS_RATES=(0.0 0.05 0.10 0.15 0.20)
        fi

        export BENCHMARK_CSV="/workspace/cluster_benchmark_results.csv"
        export BENCHMARK_JSON="/workspace/cluster_benchmark_results.json"

        echo "================================================================="
        echo "🚁 Live Multi-Container Swarm Benchmark Sweep"
        echo "   Scales to evaluate:     ${SCALES[*]}"
        echo "   Loss Rates to evaluate: ${LOSS_RATES[*]}"
        echo "   Rounds per config:      $TARGET_RUNS"
        echo "   Drone Container Memory: $TARGET_MEM"
        echo "   Drone Container CPUs:   $TARGET_CPUS"
        echo "   Output CSV:             $PWD/cluster_benchmark_results.csv"
        echo "   Output JSON:            $PWD/cluster_benchmark_results.json"
        echo "================================================================="

        for N in "${SCALES[@]}"; do
            # Determine profile configurations for this scale
            if [ -n "$CUSTOM_KA" ] && [ -n "$CUSTOM_KS" ]; then
                CONFIGS_TO_RUN=("Custom:$CUSTOM_KA:$CUSTOM_KS")
            else
                BAL_KA=$(awk "BEGIN {print int($N * 0.70 + 0.5)}")
                BAL_KS=$(awk "BEGIN {print int($N * 0.40 + 0.5)}")
                HA_KA=$(awk "BEGIN {print int($N * 0.60 + 0.5)}")
                HA_KS=$(awk "BEGIN {print int($N * 0.30 + 0.5)}")
                STRICT_KA=$(awk "BEGIN {print int($N * 0.80 + 0.5)}")
                STRICT_KS=$(awk "BEGIN {print int($N * 0.50 + 0.5)}")
                LEG_KA=$(awk "BEGIN {print int($N * 0.70 + 0.5)}")
                LEG_KS=$(awk "BEGIN {print int($N * 0.70 + 0.5)}")

                CONFIGS_TO_RUN=(
                    "Dual-Threshold Balanced:$BAL_KA:$BAL_KS"
                    "Dual-Threshold High-Availability:$HA_KA:$HA_KS"
                    "Dual-Threshold Strict:$STRICT_KA:$STRICT_KS"
                    "Legacy Baseline:$LEG_KA:$LEG_KS"
                )
            fi

            for CFG in "${CONFIGS_TO_RUN[@]}"; do
                IFS=':' read -r PROF_NAME KA KS <<< "$CFG"

                for LOSS in "${LOSS_RATES[@]}"; do
                    LOSS_PCT=$(awk "BEGIN {print int($LOSS * 100)}")

                    if [ "$IS_RESUME" -eq 1 ]; then
                        ALREADY_DONE=$(python3 -c "
import csv, os, sys
csv_path = '$PWD/cluster_benchmark_results.csv'
if not os.path.exists(csv_path):
    sys.exit(1)
try:
    with open(csv_path, 'r', newline='') as f:
        reader = csv.DictReader(f)
        for r in reader:
            if abs(int(r.get('swarm_size_n', 0)) - int('$N')) <= 3 and r.get('profile_name') == '$PROF_NAME' and abs(float(r.get('loss_rate', 0.0)) - float('$LOSS')) < 0.001:
                if int(r.get('runs_accepted', 0)) > 0:
                    sys.exit(0)
except Exception:
    pass
sys.exit(1)
" 2>/dev/null && echo "1" || echo "0")

                        if [ "$ALREADY_DONE" = "1" ]; then
                            echo "⏭️  [Skipping] n=$N | $PROF_NAME | Loss=${LOSS_PCT}% already completed successfully in CSV."
                            continue
                        fi
                    fi

                    echo ""
                    echo "-----------------------------------------------------------------"
                    echo "🚀 [Scale n=$N | $PROF_NAME] Loss=${LOSS_PCT}%"
                    echo "   ka=$KA approvals, ks=$KS shares | $TARGET_RUNS rounds"
                    echo "-----------------------------------------------------------------"

                    docker compose down -v >/dev/null 2>&1 || true

                    export NUM_DRONES="$N"
                    export SWARM_KA="$KA"
                    export SWARM_KS="$KS"
                    export THRESHOLD="$KS"
                    export PACKET_LOSS="$LOSS"
                    export PROFILE_NAME="$PROF_NAME"
                    export BENCHMARK_MODE="1"
                    export BENCHMARK_ROUNDS="$TARGET_RUNS"
                    export DRONE_MEM_LIMIT="$TARGET_MEM"
                    export DRONE_CPU_LIMIT="$TARGET_CPUS"

                    docker compose up -d --scale drone="$N"

                    echo "[*] Swarm containers active. Waiting for Ground Station consensus..."
                    GS_STATUS=$(docker wait pqc_ground_station 2>/dev/null || echo "1")

                    docker logs pqc_ground_station 2>/dev/null || true

                    echo "[*] Tearing down n=$N containers..."
                    docker compose down >/dev/null 2>&1 || true

                    if [ "$GS_STATUS" != "0" ]; then
                        echo "⚠️  [Warning] Ground Station exited with status $GS_STATUS on n=$N ($PROF_NAME, Loss=${LOSS_PCT}%)."
                    else
                        echo "[+] Completed n=$N | $PROF_NAME | Loss=${LOSS_PCT}% successfully."
                    fi
                done
            done
        done

        echo ""
        echo "================================================================="
        echo "🎉 Live Multi-Container Cluster Benchmark Complete Across Configurations!"
        echo "   Physical Cluster CSV:  $PWD/cluster_benchmark_results.csv"
        echo "   Physical Cluster JSON: $PWD/cluster_benchmark_results.json"
        echo "   Simulation Model CSV:  $PWD/benchmark_results.csv"
        echo "   Simulation Model JSON: $PWD/benchmark_results.json"
        echo "================================================================="
        if [ -f "$PWD/cluster_benchmark_results.csv" ]; then
            echo ""
            echo "📊 Live Cluster Benchmark Results (Last 12 Records):"
            tail -n 13 "$PWD/cluster_benchmark_results.csv" | awk -F',' '{printf "%-5s | %-28s | %-4s | %-4s | %-5s | %-7s | %-12s | %-10s\n", $1, $2, $3, $4, $6, $14, $15, $16}'
        fi
        ;;

    up)
        DRONES=${2:-$DEFAULT_DRONES}
        MEM=${3:-$DEFAULT_MEMORY}
        CPUS=${4:-$DEFAULT_CPUS}

        echo "================================================================="
        echo "[*] Launching Swarm Cluster:"
        echo "    - MQTT Broker:     1"
        echo "    - Ground Station:  1"
        echo "    - Autonomous Drones: $DRONES"
        echo "    - Memory Limit:    $MEM per drone"
        echo "    - CPU Limit:       $CPUS cores per drone"
        echo "================================================================="

        export DRONE_MEM_LIMIT="$MEM"
        export DRONE_CPU_LIMIT="$CPUS"
        export NUM_DRONES="$DRONES"

        docker compose up -d --build --scale drone="$DRONES"
        echo "[+] Swarm running! View logs with: ./docker_commands.sh logs"
        ;;

    down)
        echo "[*] Tearing down swarm containers and virtual mesh network..."
        docker compose down
        ;;

    logs)
        docker compose logs -f
        ;;

    plot)
        echo "[*] Generating all publication-quality benchmark plots..."
        if [ -f "$PWD/venv/bin/python3" ]; then
            "$PWD/venv/bin/python3" "$PWD/plot_comparison.py"
        else
            python3 "$PWD/plot_comparison.py"
        fi
        echo "[+] Plots generated in $PWD/paper/result/"
        ;;

    help|*)
        show_help
        ;;
esac
