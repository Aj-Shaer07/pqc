# Post-Quantum Cryptographic Drone Swarm Coordination Framework

A decentralized, post-quantum threshold cryptography framework for autonomous drone swarms.

## Architecture Highlights
- **Post-Quantum Digital Signatures**: Falcon-512 (NIST Round 3 PQC standard).
- **Threshold Cryptography**: Shamir's $(k, n)$ Secret Sharing with CSPRNG (`secrets.randbelow`) and Horner's rule evaluation.
- **Decentralized Execution**: No centralized `ThresholdEngine`. Verification, peer approval aggregation, and key reconstruction are performed independently inside each autonomous drone node.
- **Authenticated Encryption**: ChaCha20-Poly1305 AEAD for mission command payloads.

---

## Repository Structure

```text
├── falcon_py/                   # Falcon-512 Python implementation (vendored from tprest/falcon.py)
├── pqc-drone-swarm/             # Core swarm package & benchmarking suite
│   ├── pyproject.toml           # Swarm package manifest
│   ├── run_simulation.py        # Multi-configuration parallel simulation benchmark runner
│   ├── run_ground_station.py    # Docker Ground Station daemon & metric harvester
│   ├── run_drone_node.py        # Autonomous Docker drone container daemon
│   ├── src/pqc_swarm/           # Modular library
│   │   ├── crypto/              # FalconSigner, SSS, and AEAD modules
│   │   ├── models/              # Command, Approval, Share dataclasses, TrustRegistry
│   │   ├── nodes/               # DroneNode and GroundStationNode
│   │   └── sim/                 # Decentralized simulation harness
│   ├── tests/                   # Automated unit tests (18 test cases)
│   └── notebooks/               # Research notebooks & legacy exploration
├── paper/
│   └── result/                  # Publication-quality benchmark evaluation figures (PNG)
├── docker_commands.sh           # Unified Docker simulation & cluster controller CLI
├── docker-compose.yml           # Docker multi-container service definition
├── plot_comparison.py           # Publication benchmark plotting & comparative analysis suite
├── benchmark_results.csv        # In-memory simulation benchmark dataset (100 runs, 27 columns)
├── benchmark_results.json       # Simulation dataset + Hardware sensitivity + Red-team battery
├── cluster_benchmark_results.csv # Live multi-container Docker cluster dataset (100 runs, 27 columns)
├── cluster_benchmark_results.json # Live cluster JSON dataset
└── system_architecture.png      # High-level protocol diagram
```

---

## Vendored Dependencies & Attribution

> [!NOTE]
> **Falcon-512 Implementation (`falcon_py/`)**:
> The `falcon_py` module in this repository is directly vendored from the official Python reference implementation by **Thomas Prest**:
> - Upstream Repository: [https://github.com/tprest/falcon.py](https://github.com/tprest/falcon.py)
> - Authors: Thomas Prest et al. (Falcon Signature Scheme co-designer)
> - License: MIT
> 
> To ensure seamless reproduction across physical testbeds, Docker containers, and different developer environments without external submodule sync issues, the source code is included directly with an added `pyproject.toml` enabling editable `pip` installation.

---

## Quickstart & Installation

### 1. Clone the Repository
```bash
git clone https://github.com/Aj-Shaer07/pqc.git
cd pqc
```

### 2. Set Up Virtual Environment & Dependencies
```bash
python3 -m venv venv
source venv/bin/activate

# Install vendored Falcon package
pip install -e falcon_py

# Install pqc-drone-swarm package
pip install -e pqc-drone-swarm
```

### 3. Run Automated Tests
```bash
python3 -m unittest pqc-drone-swarm/tests/test_swarm.py
```

### 4. Run Benchmark Simulation
```bash
cd pqc-drone-swarm

# Run all standard configurations (k=3,n=5), (5,10), (10,20), (25,50)
python3 run_simulation.py

# Or run a single custom configuration
python3 run_simulation.py --single -k 3 -n 5 -r 1
```

---

## Docker Usage & Simulation

All docker commands are available through the unified helper script [`docker_commands.sh`](docker_commands.sh).

### Interactive Swarm Controller (`docker_commands.sh`)
```bash
# View all available commands
./docker_commands.sh

# Build base Docker image
./docker_commands.sh build

# Run unit tests inside container
./docker_commands.sh test

# Run multi-process parallel simulation sweep across host CPU cores (exports benchmark_results.csv/json)
./docker_commands.sh simulate

# Run live multi-container cluster benchmark sweep across scales (n = 10..50) with clean teardown per scale:
./docker_commands.sh cluster-sweep

# Spin up 5 drones with default constraints (256MB RAM, 0.5 CPU each):
./docker_commands.sh up 5

# Simulate constrained hardware (e.g. 10 drones with 128MB RAM and 0.25 CPU each):
./docker_commands.sh up 10 128m 0.25

# View live logs across all containers:
./docker_commands.sh logs

# Inject Red-Team adversary attacks (eavesdrop, tamper, replay, wrong-key, rogue-gs):
./docker_commands.sh attack demo

# Tear down cluster and network:
./docker_commands.sh down
```

---

## Comparative Analysis & Visualization Suite

Generate all publication-quality comparison figures comparing the in-memory simulation model against the live multi-container virtualized cluster across scales and RF loss rates:

```bash
# Generates all 18 comparative figures directly into paper/result/
python3 plot_comparison.py
```



