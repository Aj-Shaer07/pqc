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

## 🛡️ Phase 3: Protocol Hardening & Swarm Resilience (IN PROGRESS 🟡)
- [x] **Replay Attack Defense**:
  - [x] Enforce timestamp freshness validity windows (e.g. within $\pm 5$ seconds).
  - [x] Local nonce caching table to reject replayed commands and approvals with automatic TTL pruning.
- [x] **Broadcast Encryption**:
  - [x] Encrypt MQTT broadcast traffic (`swarm/shares`) via ChaCha20-Poly1305 AEAD under Swarm Mesh Session Key ($K_{\text{mesh}}$) to protect Shamir coordinates $(x, y)$ from passive eavesdropping.
  - [x] Zero-leakage wire serialization: Plaintext coordinates $(x, y)$ are omitted from network dictionaries when encrypted.
  - [x] AEAD authentication and anti-replay validation on received shares; rejection of tampered shares and unauthorized eavesdroppers without $K_{\text{mesh}}$.
- [x] **Distributed Security Alert Telemetry**:
  - [x] Real-time `SECURITY_ALERT` emission over `swarm/telemetry` for invalid signatures, AEAD MAC tag failures, replay duplicates, and untrusted peers.
  - [x] Ground Station telemetry harvester captures and logs live security alerts across the cluster.
- [x] **Anti-DoS Nonce Exhaustion Protection**:
  - [x] Strict decoupling of freshness checking (`check_freshness()`) from state commitment (`record_seen()`), ensuring unauthenticated packets cannot burn legitimate nonces.
- [x] **Empirical Red-Team Adversarial Test Battery (`simulate_adversary.py`)**:
  - [x] **Wire Sniffing & Shannon Entropy Analysis**: Proves zero plaintext coordinate leakage and $H(X) \approx 6.88$–$7.99$ bits/byte indistinguishability.
  - [x] **Rogue Node Isolation (Ingress & Egress)**: Evaluates both ingress decryption failure (`InvalidTag`) and egress live-swarm rejection of rogue share injections.
  - [x] **MitM Ciphertext Tampering**: Proves dual-layer rejection (Falcon-512 signature failure & Poly1305 MAC tag failure).
  - [x] **Temporal Replay Attack**: Demonstrates `AntiReplayFilter` state rejection of replayed authentic packets with valid signatures.
  - [x] **Unauthorized Ground Station Forgery**: Validates swarm-wide rejection of commands signed by unpinned Falcon-512 keys.
  - [x] **Standalone Multi-Vector Battery**: In-memory test harness (`./docker_commands.sh attack demo`) passing 100%.
- [ ] **Rogue Ground Station Defense (Autonomous Safety)**:
  - [ ] Autonomous safety policies & geofence checks (drones reject out-of-boundary commands even if signed by GS).
  - [ ] Multi-operator signature verification (require $M$-of-$N$ GS signatures).
- [ ] **Dynamic Swarm Membership**:
  - [ ] Trust registry revocation lists broadcast over `swarm/registry`.
  - [ ] Dynamic onboarding of replacement drones with fresh shares without altering the master mission key.
- [ ] **Node Drop-out & Fail-safe Handling**:
  - [ ] Swarm fault tolerance testing (active drones $\ge k \implies$ mission proceeds).
  - [ ] Autonomous Return-to-Launch (RTL) trigger when active drones $< k$.
- [ ] **Performance Measurement & Telemetry Metrics**:
  - [x] **Cryptographic & Protocol Latency**: Quantify Falcon-512 signing/verification, SSS Lagrange reconstruction, and AEAD encryption/decryption durations per node.
  - [x] **End-to-End Consensus Time**: Measure latency from Ground Station command dispatch $\to$ peer approvals $\to$ share exchange $\to$ decentralized execution across $N$ nodes.
  - [ ] **Network & Bandwidth Overhead**: Profile payload wire sizes (Falcon public key ~897B, signature ~666B, ciphertext, encrypted shares) and MQTT topic traffic volume.
  - [ ] **Hardware Resource Profiling**: Track per-container CPU utilization spikes and RAM RSS (MB) under throttled Docker constraints (e.g., 256MB/512MB RAM, 0.5/1.0 CPUs).
  - [x] **Automated Metrics Telemetry**: Collect distributed metrics via `swarm/telemetry` and report timing breakdowns on Ground Station.

---

## 🔬 Phase 4: Formal Security Verification & Robustness (UPCOMING ⏳)
- [ ] **Mathematical Verification (BAN Logic)**:
  - [ ] Formalize idealizations, assumptions, and logical derivations for mutual authentication, authority, and freshness.
- [ ] **Automated Symbolic Verification (ProVerif / Tamarin Provers)**:
  - [ ] Model the protocol under the **Dolev-Yao** network attacker model.
  - [ ] Model ephemeral compromise under the **Canetti-Krawczyk (CK)** adversary model.
  - [ ] Formally prove **Secrecy / Confidentiality** ($\text{Attacker} \not\vdash K_{\text{mission}}$ when $< k$ shares compromised).
  - [ ] Formally prove **Injective Agreement** (Mutual authentication between GS and Swarm).
  - [ ] Formally prove **Non-Frameability / Unforgeability** (Adversary cannot forge honest drone approvals).
  - [ ] Formally prove **Anti-Replay Invariance** across temporal sessions.
  - [ ] Formally prove **Forward Secrecy (PFS)** of completed mission commands.
- [ ] **Post-Quantum Cryptographic & Hardness Analysis**:
  - [ ] Quantum bit-security quantification for Falcon-512 (Core-SVP hardness via BKZ-2.0 lattice reduction simulation).
  - [ ] Classical vs Post-Quantum comparison (Falcon-512 vs ECDSA/RSA-2048 key size, signature size, and verification overhead).
- [ ] **Advanced Swarm Fault Tolerance**:
  - [ ] **Byzantine Share Corruption**: Malicious nodes broadcasting corrupted Shamir shares $(x, y')$ to attempt denial-of-reconstruction.
  - [ ] **Swarm Drop-out & Split-Brain**: Rapid dropping of $N - k + 1$ containers to verify autonomous abort and RTL fail-safe.

