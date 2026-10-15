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
    echo "  build                  Build the base Debian-slim Docker image"
    echo "  test                   Run unit tests inside an isolated container"
    echo "  sim-single             Run single benchmark inside container (k=3, n=5)"
    echo "  sim-all                Run full paper benchmarks (all configs, k/n)"
    echo "  up [N] [MEM] [CPUS]    Start multi-container swarm with N drones"
    echo "                         (Defaults: N=$DEFAULT_DRONES, MEM=$DEFAULT_MEMORY, CPUS=$DEFAULT_CPUS)"
    echo "  attack [demo|eavesdrop|tamper|wrong-key|replay|rogue-gs] [DUR] [TARGET]"
    echo "                         Run Red-Team attack battery against the swarm (defaults: demo)"
    echo "  down                   Stop and remove all swarm containers & network"
    echo "  logs                   Follow real-time logs from all swarm nodes"
    echo ""
    echo "Examples:"
    echo "  ./docker_commands.sh build"
    echo "  ./docker_commands.sh test"
    echo "  ./docker_commands.sh attack demo         # In-memory security validation battery"
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
        docker run --rm pqc-drone-swarm:latest
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

    help|*)
        show_help
        ;;
esac
