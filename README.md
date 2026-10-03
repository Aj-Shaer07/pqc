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
├── falcon_py/               # Falcon-512 Python implementation (vendored from tprest/falcon.py)
├── pqc-drone-swarm/         # Core swarm package & benchmarking suite
│   ├── pyproject.toml       # Swarm package manifest
│   ├── run_simulation.py    # Multi-configuration benchmark runner (CLI)
│   ├── src/pqc_swarm/       # Modular library
│   │   ├── crypto/          # FalconSigner, SSS, and AEAD modules
│   │   ├── models/          # Command, Approval, Share dataclasses, TrustRegistry
│   │   ├── nodes/           # DroneNode and GroundStationNode
│   │   └── sim/             # Decentralized simulation harness
│   ├── tests/               # Automated unit tests
│   └── notebooks/           # Research notebooks & legacy exploration
└── system_architecture.png  # High-level protocol diagram
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

All docker commands are also available in [`docker_commands.sh`](docker_commands.sh).

### 1. Build the Lightweight Image (Debian Slim)
```bash
docker build -t pqc-drone-swarm:latest .
```

### 2. Run Test Battery inside Container
```bash
docker run --rm pqc-drone-swarm:latest
```

### 3. Run Benchmark Simulation inside Container
```bash
# Single configuration (k=3, n=5)
docker run --rm pqc-drone-swarm:latest python3 run_simulation.py --single -k 3 -n 5 -r 1

# Full benchmark across all configurations (3,5), (5,10), (10,20), (25,50)
docker run --rm pqc-drone-swarm:latest python3 run_simulation.py -r 3
```

### 4. Multi-Container Swarm (Docker Compose)
Spins up the Eclipse Mosquitto MQTT broker, Ground Station, and dynamically scales $N$ drone containers:

```bash
# Spin up broker, Ground Station, and 5 independent drone containers:
docker compose up --build --scale drone=5

# Spin up with 10 drone containers:
docker compose up --scale drone=10

# Tear down containers and simulated network:
docker compose down
```


