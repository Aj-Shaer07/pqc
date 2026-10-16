# PQC Drone Swarm - Project State & Roadmap Tracker

Last Updated: 2026-10-16
Repository: `https://github.com/Aj-Shaer07/pqc.git`

---

## 📌 Canonical Notation & Parameter Standardization Reference

To ensure strict mathematical and architectural uniformity across all documentation, source code, and benchmarking modules, the following standard notation is enforced throughout this repository:

| Symbol / Parameter | Canonical Definition | Standard Values / Ranges | Documented Equivalents (Unified) |
| :--- | :--- | :--- | :--- |
| **$n$** | Active swarm fleet size (number of drone nodes) | $n = \vert \text{Registered Drones} \vert \in [3, 50]$ | Lowercase $n$ strictly (never capital $N$) |
| **$k_a$** | Command authorization threshold (peer approvals) | $k_s \le k_a \le n$ (e.g., $k_a \in \{3, 5, 7\}$) | Replaces generic $k$ for peer approval quorum |
| **$k_s$** | Secret reconstruction threshold (Shamir polynomial shares) | $2 \le k_s \le k_a \le n$ (e.g., $k_s \in \{3, 5\}$) | Replaces generic $k$ for polynomial degree $(k_s - 1)$ |
| **$N$** | Statistical benchmark sample size (iterations/runs) | $N \ge 100$ runs ($N=10$ pilot) | Capital $N$ strictly reserved for sample size |
| **$K_{\text{mesh}}$** | Swarm Mesh Session Key (AEAD broadcast encryption) | 256-bit symmetric key (`secrets.token_bytes(32)`) | Mesh broadcast cipher key |
| **$K_{\text{mission}}$ ($S$)** | Master Mission Key ($S = f(0) \pmod p$) | 256-bit key embedded in $\mathbb{F}_p$ ($p = 2^{521} - 1$) | Mission payload cipher key |
| **$W$** | Temporal anti-replay sliding window | $W = \pm 5.0\text{ s}$ ($2W = 10.0\text{ s}$ TTL cache) | Freshness window |
| **$p_{\text{loss}}$** | Simulated RF mesh packet loss probability | $p_{\text{loss}} \in \{0.05, 0.10, 0.20\}$ (5%, 10%, 20%) | Loss probability |
| **$m\text{-of-}n_{\text{gs}}$** | Multi-operator Ground Station threshold signature | $m \le n_{\text{gs}}$ (e.g., 2-of-3 GS operators) | Replaces generic $M$-of-$N$ |
| **RAM Quotas** | Container memory cgroup limit | `256m` (256 MB default); `128m`, `512m` evaluated | Standardized MB / cgroup syntax |
| **CPU Quotas** | Container CPU core throttling quota | `0.5` cores (default); `0.25`, `1.0` evaluated | Standardized core allocation |
| **Payload Ceiling** | MQTT wire frame byte ceiling (`MAX_WIRE_PAYLOAD_BYTES`) | $128\text{ KB}$ ($131{,}072\text{ bytes}$) | Wire ingress/publish DoS barrier |

---

## 📌 Phase 0: Code Modernization & Packaging (COMPLETED ✅)
- [x] Decompose monolithic script (`implementation.py`) into modular package `pqc_swarm`.
- [x] Cryptographic hardening:
  - [x] Migrate SSS to CSPRNG (`secrets.randbelow`) and Horner's polynomial rule over Mersenne prime field $\mathbb{F}_p$ ($p = 2^{521} - 1$).
  - [x] Implement ChaCha20-Poly1305 AEAD authenticated encryption wrapper for mission command payloads.
  - [x] Implement Falcon-512 post-quantum digital signature abstraction.
- [x] Make `tprest/falcon.py` an installable Python package via `pyproject.toml`.
- [x] Full top-level exports in `src/pqc_swarm/__init__.py`.
- [x] Automated unit test suite (`tests/test_swarm.py`) passing 100%.
- [x] CLI simulation benchmark runner (`run_simulation.py`) supporting $(k, n) \in \{(3,5), (5,10), (10,20), (25,50)\}$.
- [x] Root `README.md` with complete attribution and usage instructions.
- [x] Git repository initialization and commit history established on `main`.

---

## 🚀 Phase 1: Decentralized Coordination & Networking Layer (COMPLETED ✅)
- [x] **Elimination of Centralized Threshold Engine**:
  - [x] Threshold verification logic embedded independently inside every `DroneNode`.
  - [x] Drones maintain local peer approval tables and share caches without any central coordinator.
- [x] **P2P Gossip & MQTT Communication Layer**:
  - [x] `SwarmMQTTTransport` wrapper over `paho-mqtt` (`src/pqc_swarm/networking/mqtt_client.py`).
  - [x] Swarm topic routing:
    - `swarm/commands` (Ground Station broadcast)
    - `swarm/approvals` (Drone-to-drone peer gossip)
    - `swarm/shares` (Threshold key reconstruction)
    - `swarm/registry` (Dynamic trust & public key announcements)
    - `swarm/telemetry` (Execution acknowledgment & latency metrics)
  - [x] Autonomous Drone container daemon (`run_drone_node.py`).
  - [x] Ground Station command dispatcher daemon (`run_ground_station.py`).

---

## 🐳 Phase 2: Multi-Container Hardware Simulation via Docker (COMPLETED ✅)
- [x] **Base Docker Image (`Dockerfile`)**:
  - [x] Lightweight Debian Slim base (`python:3.14-slim` matching host architecture and `falcon_py`).
  - [x] Pre-compiled cryptographic dependencies (`pycryptodome`, `cryptography`, `numpy`, `paho-mqtt`).
  - [x] Multi-package editable installs (`falcon_py` + `pqc-drone-swarm`).
- [x] **Docker Compose Topology (`docker-compose.yml`)**:
  - [x] $1\times$ Eclipse Mosquitto MQTT broker (`pqc_mqtt_broker`).
  - [x] $1\times$ Ground Station container (`pqc_ground_station`, 512 MB RAM, 1.0 CPU).
  - [x] $n\times$ Autonomous Drone containers (`--scale drone=n`, 256 MB RAM, 0.5 CPU default).
  - [x] Isolated virtual bridge mesh network (`swarm-net`).
  - [x] Live code volume mounting (`./pqc-drone-swarm:/app/pqc-drone-swarm`) for rapid zero-downtime testing.
- [x] **Hardware Resource Constraints**:
  - [x] Dynamic RAM limits per container (`256m` [256 MB] default; `128m` [128 MB], `512m` [512 MB] evaluated).
  - [x] Dynamic CPU core throttling (`0.5` cores default; `0.25`, `1.0` cores evaluated).
- [x] **Interactive CLI Controller (`docker_commands.sh`)**:
  - [x] Standard operational commands: `build`, `test`, `sim-single`, `sim-all`, `up [n] [MEM] [CPUS]`, `down`, `logs`.
  - [x] Automatic container alias resolution for targeted attacks (`DRONE_2`, `drone-7`, `2`, `10` $\to$ Docker container hex IDs) with collision-proof regex matching.

---

## 🛡️ Phase 3: Protocol Hardening, Swarm Resilience & Empirical Profiling (IN PROGRESS 🟡)

### 3.1 Implemented & Hardened Protocol Subsystems (COMPLETED ✅)
- [x] **Exact Dynamic $(k, n)$ SSS Generation**:
  - [x] Eliminated static `shares_pool = 100` pre-generation limitation.
  - [x] Ground Station dynamically discovers active fleet size ($n = |\text{Registered Drones}|$) and computes exact $(k, n)$ polynomial evaluation points.
  - [x] Cluster-wide `peer_registry` broadcast eliminates untrusted peer rejections upon dynamic scaling.
- [x] **Intrusion Detection System (IDS) Decoupling**:
  - [x] Continuous cryptographic share validation: Removed premature early return on executed commands in `run_drone_node.py`. Every peer share (early, on-time, or late) undergoes Anti-Replay, Falcon-512 signature, and Poly1305 MAC tag verification.
  - [x] Single-execution enforcement: Local payload execution triggers strictly once upon satisfying threshold quorum, while subsequent malicious or tampered packets are flagged via `SECURITY_ALERT` telemetry.
- [x] **Replay Attack Defense**:
  - [x] Enforce timestamp freshness validity windows ($W = \pm 5.0\text{ s}$).
  - [x] Local nonce caching table to reject replayed commands and approvals with automatic TTL pruning ($2W = 10.0\text{ s}$).
- [x] **Broadcast Encryption**:
  - [x] Encrypt MQTT broadcast traffic (`swarm/shares`) via ChaCha20-Poly1305 AEAD under Swarm Mesh Session Key ($K_{\text{mesh}}$) to protect Shamir coordinates $(x, y)$ from passive eavesdropping.
  - [x] Zero-leakage wire serialization: Plaintext coordinates $(x, y)$ are omitted from network dictionaries when encrypted.
  - [x] AEAD authentication and anti-replay validation on received shares; rejection of tampered shares and unauthorized eavesdroppers without $K_{\text{mesh}}$.
- [x] **Distributed Security Alert Telemetry**:
  - [x] Real-time `SECURITY_ALERT` emission over `swarm/telemetry` for invalid signatures, AEAD MAC tag failures, replay duplicates, and untrusted peers.
  - [x] Ground Station telemetry harvester captures and logs live security alerts across the cluster.
- [x] **Anti-DoS Nonce Exhaustion Protection**:
  - [x] Strict decoupling of freshness checking (`check_freshness()`) from state commitment (`record_seen()`), ensuring unauthenticated packets cannot burn legitimate nonces.
- [x] **Comprehensive Cryptographic, Network & System Hardening**:
  - [x] **Cryptographic Hardening**:
    - [x] Enforced SSS coordinate bounds: $1 \le x < p$ and $0 \le y < p$.
    - [x] Strict $x=0$ rejection preventing trivial secret leakage ($f(0) = S = K_{\text{mission}}$).
    - [x] Duplicate $x$-coordinate detection during Lagrange interpolation to prevent division-by-zero modular inversion crashes.
    - [x] Enforced single-drone share quota (`share_contributors`) to prevent a single compromised peer from inflating shares to reach reconstruction threshold $k_s$.
    - [x] Strict AEAD parameter enforcement: 32-byte key, 12-byte nonce, and $\ge 16$-byte Poly1305 MAC tag validation.
  - [x] **Network Hardening**:
    - [x] Enforced 128 KB wire payload ceiling (`MAX_WIRE_PAYLOAD_BYTES = 131072`) on both publish and ingress handlers to protect throttled 256 MB RAM companion containers from memory exhaustion DoS.
    - [x] Exception isolation in MQTT message callback handlers, ensuring malformed packet injections cannot crash the client background network thread.
    - [x] Cryptographic client ID randomization (`secrets.token_hex(4)`) preventing broker connection collisions and involuntary client dropouts.
  - [x] **System Hardening**:
    - [x] Full thread safety via reentrant locks (`threading.RLock`) across `DroneNode`, `TrustRegistry`, and `AntiReplayFilter`.
    - [x] Bounded memory pruning (`max_entries = 4096`) under sliding window packet flood attacks.
    - [x] Clean SIGINT/SIGTERM process teardown and socket disposal.
  - [x] **Automated Hardening Verification**: Expanded automated test suite to 17/17 tests passing (100%) inside isolated Docker containers and local environments.
- [x] **Empirical Red-Team Adversarial Test Battery (`simulate_adversary.py`)**:
  - [x] **Wire Sniffing & Shannon Entropy Analysis**: Proves zero plaintext coordinate leakage and $H(X) \approx 6.88\text{--}7.99\text{ bits/byte}$ indistinguishability from random noise.
  - [x] **Rogue Node Isolation (Ingress & Egress)**: Evaluates both ingress decryption failure (`InvalidTag`) and egress live-swarm rejection of rogue share injections.
  - [x] **MitM Ciphertext Tampering**: Proves dual-layer rejection (Falcon-512 signature failure & Poly1305 MAC tag failure) with targeted node resolution (e.g. `DRONE_2` $\to$ 9/9 rejections across the swarm).
  - [x] **Temporal Replay Attack**: Demonstrates `AntiReplayFilter` state rejection of replayed authentic packets with valid signatures.
  - [x] **Unauthorized Ground Station Forgery**: Validates swarm-wide rejection (10/10 nodes) of commands signed by unpinned Falcon-512 keys.
  - [x] **Standalone Multi-Vector Battery**: In-memory test harness (`./docker_commands.sh attack demo`) passing 100%.

### 3.2 Journal Refinements & Extended Empirical Profiling (IN PROGRESS 🟡)
- [ ] **Decoupled Dual-Threshold Architecture ($k_a, k_s$)**:
  - [ ] Parameterize independent command authorization threshold ($k_a$ peer approvals) and key reconstruction threshold ($k_s$ Shamir shares), where $k_s \le k_a \le n$.
  - [ ] Evaluate security and availability trade-offs between authorization rigor ($k_a$) and mission availability ($k_s$) under node dropouts and packet loss.
- [ ] **Statistical Rigor & Sample Size Scaling ($N \ge 100$)**:
  - [ ] Scale automated benchmark harness from $N=10$ pilot runs to $N \ge 100$ runs across baseline configurations $(k, n) \in \{(3,5), (5,10), (10,20), (25,50)\}$ and decoupled dual-threshold $(k_a, k_s, n)$ configurations.
  - [ ] Compute and report full statistical distributions: Mean ($\mu$), Standard Deviation ($\pm \sigma$), 95% Confidence Intervals, and Median/IQR.
- [ ] **Comprehensive Performance Measurement & Telemetry Metrics**:
  - [x] **Cryptographic & Protocol Latency**: Quantify Falcon-512 signing/verification, SSS Lagrange reconstruction, and AEAD encryption/decryption durations per node.
  - [x] **End-to-End Consensus Time**: Measure latency from Ground Station command dispatch $\to$ peer approvals $\to$ share exchange $\to$ decentralized execution across $n$ nodes.
  - [x] **Automated Metrics Telemetry**: Collect distributed metrics via `swarm/telemetry` and report timing breakdowns on Ground Station.
  - [ ] **Network & Bandwidth Wire Overhead Profiling**: Profile exact wire payload sizes: Commands ($\approx 1.2\text{ KB}$), Approvals ($\approx 780\text{ B}$), Encrypted Shares ($\approx 850\text{ B}$), and Telemetry ($\approx 350\text{ B}$). Quantify aggregate bandwidth (bytes/sec) over MQTT topics as swarm scales from $n=5$ to $n=50$.
  - [ ] **Hardware Resource Profiling (Cgroups / Flight Computer Simulation)**: Instrument per-container memory RSS (MB) tracking via `/sys/fs/cgroup/memory.current` / `psutil`. Profile CPU utilization spikes (%) during peak concurrent Falcon-512 verification under constrained 0.5-core limits.
- [ ] **Varying Network Conditions Simulation (Packet Loss & Jitter)**:
  - [ ] Implement simulated RF mesh loss rates ($p_{\text{loss}} \in \{0.05, 0.10, 0.20\}$, i.e., 5%, 10%, 20%) and radio propagation jitter.
  - [ ] Quantify threshold consensus success rates and delay impact when $n > k_a \ge k_s$.
- [ ] **Dynamic Swarm Membership, Churn & Fail-Safe Handling**:
  - [ ] Trust registry revocation lists broadcast over `swarm/registry`.
  - [ ] Dynamic onboarding of replacement drones with fresh shares without altering the master mission key ($K_{\text{mission}}$).
  - [ ] Swarm fault tolerance testing (active drones $\ge k_a \ge k_s \implies$ mission proceeds).
  - [ ] Autonomous Return-to-Launch (RTL) fail-safe trigger when active drones $< k_a$ (authorization quorum lost) or $< k_s$ (reconstruction impossible).
- [ ] **Rogue Ground Station Defense (Autonomous Safety)**:
  - [ ] Autonomous safety policies & geofence checks (drones reject out-of-boundary commands even if signed by GS).
  - [ ] Multi-operator signature verification (require $m$-of-$n_{\text{gs}}$ Ground Station operator signatures).

---

## 🔬 Phase 4: Formal Security Verification, Robustness & Comparative Analysis (UPCOMING ⏳)
- [ ] **Comparative Baseline Analysis**:
  - [ ] Falcon-512 vs. Classical Baselines (ECDSA-P256, RSA-2048) in signing time, verify time, public key size, signature size, and quantum bit-security.
  - [ ] ChaCha20-Poly1305 vs. AES-256-GCM under streaming UAV payloads.
  - [ ] Proposed PQC threshold architecture vs. recent drone swarm command authorization schemes (centralized PKI, multi-sig, PBFT).
- [ ] **Formal Asymptotic Complexity Analysis**:
  - [ ] Formulate analytical Big-$O$ complexity table (Computational & Communication) for Key Generation, Signing, Verification, SSS Evaluation (Horner's rule), and Lagrange Reconstruction in terms of $n$, $k_a$, and $k_s$.
- [ ] **Mathematical Verification (BAN Logic)**:
  - [ ] Formalize idealizations, assumptions, and logical derivations for mutual authentication, authority, and freshness.
- [ ] **Automated Symbolic Verification (ProVerif / Tamarin Provers)**:
  - [ ] Model the protocol under the **Dolev-Yao** network attacker model.
  - [ ] Model ephemeral compromise under the **Canetti-Krawczyk (CK)** adversary model.
  - [ ] Formally prove **Secrecy / Confidentiality** ($\text{Attacker} \not\vdash K_{\text{mission}}$ when $< k_s$ shares compromised).
  - [ ] Formally prove **Injective Agreement** (Mutual authentication between GS and Swarm).
  - [ ] Formally prove **Non-Frameability / Unforgeability** (Adversary cannot forge honest drone approvals).
  - [ ] Formally prove **Anti-Replay Invariance** across temporal sessions.
  - [ ] Formally prove **Forward Secrecy (PFS)** of completed mission commands.
- [ ] **Post-Quantum Cryptographic & Hardness Analysis**:
  - [ ] Quantum bit-security quantification for Falcon-512 (Core-SVP hardness via BKZ-2.0 lattice reduction simulation).
- [ ] **Collusion & Byzantine Fault Tolerance Analysis**:
  - [ ] Formal collusion resilience proof for $c < k_s$ compromised drone nodes.
  - [ ] **Byzantine Share Corruption**: Defense and detection when malicious nodes broadcast corrupted Shamir shares $(x, y')$ to attempt denial-of-reconstruction.
  - [ ] **Swarm Drop-out & Split-Brain**: Rapid dropping of $n - k_a + 1$ nodes (breaking authorization quorum) and $n - k_s + 1$ nodes (breaking reconstruction quorum) to verify autonomous abort and RTL fail-safe.
