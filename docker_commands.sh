#!/usr/bin/env bash
# ==============================================================================
# PQC Drone Swarm - Docker Command Cheat Sheet
# ==============================================================================

# 1. BUILD THE BASE IMAGE
# ------------------------------------------------------------------------------
# Build the Debian-slim base image containing Falcon-512 and pqc-drone-swarm:
docker build -t pqc-drone-swarm:latest .

# 2. RUN TESTS INSIDE DOCKER CONTAINER
# ------------------------------------------------------------------------------
# Run the automated unit tests to verify Falcon math and threshold logic in Linux:
docker run --rm pqc-drone-swarm:latest

# 3. RUN SIMULATION BENCHMARK INSIDE CONTAINER
# ------------------------------------------------------------------------------
# Quick benchmark run (k=3, n=5):
docker run --rm pqc-drone-swarm:latest python3 run_simulation.py --single -k 3 -n 5 -r 1

# Full benchmark run across all paper configurations (3,5), (5,10), (10,20), (25,50):
docker run --rm pqc-drone-swarm:latest python3 run_simulation.py -r 3

# 4. MULTI-CONTAINER SWARM VIA DOCKER COMPOSE
# ------------------------------------------------------------------------------
# Spin up Broker + Ground Station + 5 Drone containers:
docker compose up --build --scale drone=5

# Spin up Broker + Ground Station + 10 Drone containers:
docker compose up --scale drone=10

# View real-time logs across all nodes:
docker compose logs -f

# Stop and remove all containers and network:
docker compose down
