# PQC Drone Swarm - Project State & Roadmap Tracker

Last Updated: 2026-10-03
Repository: `https://github.com/Aj-Shaer07/pqc.git`

---

## 📌 Phase 0: Code Modernization & Packaging (COMPLETED ✅)
- [x] Decompose monolithic script (`implementation.py`) into modular package `pqc_swarm`.
- [x] Cryptographic hardening:
  - [x] Migrate SSS to CSPRNG (`secrets.randbelow`) and Horner's polynomial rule.
  - [x] Implement ChaCha20-Poly1305 AEAD authenticated encryption wrapper.
  - [x] Implement Falcon-512 digital signature abstraction.
- [x] Make `tprest/falcon.py` an installable Python package via `pyproject.toml`.
- [x] Full top-level exports in `src/pqc_swarm/__init__.py`.
- [x] Automated unit test suite (`tests/test_swarm.py`) passing 100%.
- [x] CLI simulation benchmark runner (`run_simulation.py`) supporting $(3,5), (5,10), (10,20), (25,50)$.
- [x] Root `README.md` with complete attribution and usage instructions.
- [x] Git repository initialization and commit history established on `main`.

---

## 🚀 Phase 1: Code Decoupling & Networking (COMPLETED ✅)
- [x] **Kill Centralized Threshold Engine**:
  - [x] Threshold verification logic embedded independently inside every `DroneNode`.
  - [x] Drones maintain local peer approval tables and share caches without central engine.
- [x] **P2P Gossip & MQTT Communication Layer**:
  - [x] `SwarmMQTTTransport` wrapper over `paho-mqtt` (`src/pqc_swarm/networking/mqtt_client.py`).
  - [x] MQTT topic routing:
    - `swarm/commands` (Ground Station broadcast)
    - `swarm/approvals` (Drone-to-drone peer gossip)
    - `swarm/shares` (Threshold key reconstruction)
    - `swarm/registry` (Dynamic trust & public key announcements)
    - `swarm/telemetry` (Execution acknowledgment)
  - [x] Autonomous Drone container daemon (`run_drone_node.py`).
  - [x] Ground Station command dispatcher daemon (`run_ground_station.py`).

---

## 🐳 Phase 2: Hardware Simulation via Docker (COMPLETED ✅)
- [x] **Base Docker Image**:
  - [x] Lightweight Debian Slim base (`python:3.14-slim` to match host Mac & falcon_py exactly).
  - [x] Pre-compiled cryptographic dependencies (`pycryptodome`, `cryptography`, `numpy`, `paho-mqtt`).
  - [x] Multi-package editable installs (`falcon_py` + `pqc-drone-swarm`).
- [x] **Docker Compose Topology (`docker-compose.yml`)**:
  - [x] 1× Eclipse Mosquitto MQTT broker (`pqc_mqtt_broker`).
  - [x] 1× Ground Station container (`pqc_ground_station`).
  - [x] $N$× Autonomous Drone containers (`--scale drone=N`).
  - [x] Isolated virtual bridge mesh network (`swarm-net`).
- [x] **Hardware Resource Constraints**:
  - [x] Dynamic RAM limits per container (`256m`, `128m`, `512m`).
  - [x] Dynamic CPU core throttling (`0.5`, `0.25`, `1.0`).
- [x] **Interactive CLI Controller (`docker_commands.sh`)**:
  - [x] Easy commands: `build`, `test`, `sim-single`, `sim-all`, `up [N] [MEM] [CPUS]`, `down`, `logs`.

---

## 🛡️ Phase 3: Protocol Hardening & Swarm Resilience (UP NEXT ⏳)
- [ ] **Replay Attack Defense**:
  - [ ] Enforce timestamp freshness validity windows (e.g. within $\pm 5$ seconds).
  - [ ] Local nonce caching table to reject replayed commands and approvals.
- [ ] **Broadcast Encryption**:
  - [ ] Encrypt MQTT broadcast traffic (pre-shared mesh session key or TLS) to protect shares from passive eavesdropping.
- [ ] **Rogue Ground Station Defense**:
  - [ ] Autonomous safety policies & geofence checks (drones reject out-of-boundary commands even if signed by GS).
  - [ ] Multi-operator signature verification (require $M$-of-$N$ GS signatures).
- [ ] **Dynamic Swarm Membership**:
  - [ ] Trust registry revocation lists broadcast over `swarm/registry`.
  - [ ] Dynamic onboarding of replacement drones with fresh shares without altering the master mission key.
- [ ] **Node Drop-out & Fail-safe Handling**:
  - [ ] Swarm fault tolerance testing (active drones $\ge k \implies$ mission proceeds).
  - [ ] Autonomous Return-to-Launch (RTL) trigger when active drones $< k$.

---

## 🔬 Phase 4: Formal Security Verification (UPCOMING ⏳)
- [ ] **BAN Logic Derivations**:
  - [ ] Formalize idealizations, assumptions, and mathematical derivations for mutual authentication, authority, and freshness.
- [ ] **Automated Prover Formal Modeling (Tamarin / ProVerif)**:
  - [ ] Model the protocol under the Dolev-Yao attacker model.
  - [ ] Formally verify secrecy of mission key and command authenticity.
  - [ ] Verify resilience against Man-in-the-Middle (MitM) and Sybil attacks.
