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
    echo "  down                   Stop and remove all swarm containers & network"
    echo "  logs                   Follow real-time logs from all swarm nodes"
    echo ""
    echo "Examples:"
    echo "  ./docker_commands.sh build"
    echo "  ./docker_commands.sh test"
    echo "  ./docker_commands.sh up 5                # Spin up 5 drones with 256MB RAM each"
    echo "  ./docker_commands.sh up 10 512m 1.0      # Spin up 10 drones with 512MB RAM & 1 CPU each"
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
