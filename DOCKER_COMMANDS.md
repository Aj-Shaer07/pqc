# Docker Simulation & Command Reference Guide

**Project:** Post-Quantum Cryptographic (PQC) Drone Swarm Coordination & Threshold Authorization  
**Repository:** `https://github.com/Aj-Shaer07/pqc.git`  
**Document Purpose:** Technical Reference for Swarm Emulation & Security Verification

---

## 1. Executive Summary & Hardware Simulation Rationale

Physical flight testing of autonomous drone swarms is costly, logistically complex, and hazardous—especially when validating cryptographic failure modes and adversarial attacks.

To evaluate real-world feasibility on resource-constrained embedded computing hardware without requiring physical UAVs, this project containerizes each network participant using **Docker** and **Docker Compose**:

```mermaid
flowchart TD
    subgraph Host["Host Machine (Linux / macOS / Windows)"]
        subgraph SwarmNet["Virtual RF Mesh Network (swarm-net bridge)"]
            Broker["pqc_mqtt_broker<br/>(Eclipse Mosquitto 2.x)<br/>Port: 1883"]
            GS["pqc_ground_station<br/>(Command Dispatcher & Harvester)<br/>Limits: 512MB RAM, 1.0 CPU"]
            D1["pqc-drone-1<br/>(Autonomous Node)<br/>Limits: 256MB RAM, 0.5 CPU"]
            D2["pqc-drone-2<br/>(Autonomous Node)<br/>Limits: 256MB RAM, 0.5 CPU"]
            Dn["pqc-drone-N<br/>(Autonomous Node)<br/>Limits: 256MB RAM, 0.5 CPU"]
            Attacker["pqc_red_team<br/>(Adversary Simulator Container)<br/>Eavesdrop / MitM / Rogue Key"]
        end
    end

    GS <-->|"swarm/commands<br/>swarm/registry<br/>swarm/telemetry"| Broker
    D1 <-->|"swarm/approvals<br/>swarm/shares<br/>swarm/telemetry"| Broker
    D2 <-->|"swarm/approvals<br/>swarm/shares<br/>swarm/telemetry"| Broker
    Dn <-->|"swarm/approvals<br/>swarm/shares<br/>swarm/telemetry"| Broker
    Attacker -.->|"Sniffing & Tampering"| Broker
```

### Why This Emulation Accurately Models Physical UAV Swarms:
1. **Isolated Operating Environments:** Every drone container runs inside an independent Linux network namespace, maintaining its own keypair, nonces, local state tables, and Shamir share.
2. **Hardware Resource Throttling:** Using Linux cgroups, each drone container is constrained to **256MB RAM** and **0.5 CPU cores** (matching low-cost companion computers such as the Raspberry Pi Zero 2W or Pixhawk companion computers).
3. **Virtual RF Mesh Broadcast (`swarm-net`):** The isolated Docker bridge network acts as the shared wireless frequency band. All communications transit via the Eclipse Mosquitto MQTT broker functioning as the virtual gossip fabric.
4. **Adversarial Red-Team Injection:** Attack containers can join the virtual network dynamically to sniff traffic, tamper with wire packets, or attempt unauthorized command execution.

---

## 2. Quick Command Reference

All operations are automated through the unified controller script:

```bash
./docker_commands.sh [COMMAND] [OPTIONS]
```

| Command | Syntax | Description |
| :--- | :--- | :--- |
| **`build`** | `./docker_commands.sh build` | Compiles dependencies and builds the base `pqc-drone-swarm:latest` Docker image. |
| **`test`** | `./docker_commands.sh test` | Runs the automated 12-test cryptographic & protocol test battery inside an isolated container. |
| **`up`** | `./docker_commands.sh up [N] [MEM] [CPUS]` | Spawns the live swarm cluster with 1 Mosquitto Broker, 1 Ground Station, and $N$ Drones with custom CPU/RAM limits. |
| **`logs`** | `./docker_commands.sh logs` | Streams real-time decentralized consensus logs across all containers. |
| **`attack`** | `./docker_commands.sh attack [MODE] [DUR] [TARGET]` | Injects Red-Team attack scenarios: `demo`, `eavesdrop`, `wrong-key`, `tamper`, `replay`, or `rogue-gs`. |
| **`sim-single`** | `./docker_commands.sh sim-single` | Runs a standalone benchmark simulation round ($k=3, n=5$) inside Docker. |
| **`sim-all`** | `./docker_commands.sh sim-all [RUNS]` | Runs the full paper benchmark matrix across $(3,5), (5,10), (10,20), (25,50)$. |
| **`down`** | `./docker_commands.sh down` | Gracefully terminates and removes all containers, networks, and volumes. |

---

## 3. Command Deep-Dive & Technical Mechanics

---

### 3.1 `build` — Base Image Compilation
```bash
./docker_commands.sh build
```

#### What It Does:
- Reads the multi-stage [Dockerfile](file:///home/aj-shaer/Desktop/pqc/Dockerfile) based on Debian Slim (`python:3.14-slim`).
- Installs minimal C-compiler toolchains (`build-essential`).
- Pre-installs optimized cryptographic libraries (`cryptography`, `pycryptodome`, `numpy`, `paho-mqtt`, `beartype`).
- Performs an editable install (`pip install -e`) of:
  - `falcon_py/`: Thomas Prest's post-quantum Falcon-512 reference implementation.
  - `pqc-drone-swarm/`: The modular drone swarm library.
- Produces a lightweight, self-contained Docker image tagged `pqc-drone-swarm:latest`.

---

### 3.2 `test` — Ephemeral Container Verification
```bash
./docker_commands.sh test
```

#### What It Does:
- Spawns a disposable container (`docker run --rm`) that executes Python's unit test runner against [tests/test_swarm.py](file:///home/aj-shaer/Desktop/pqc/pqc-drone-swarm/tests/test_swarm.py).
- **Validates 12 Security Subsystems:**
  1. Falcon-512 digital signature generation and verification.
  2. CSPRNG Shamir's Secret Sharing polynomial evaluation over $p = 2^{521} - 1$.
  3. Lagrange polynomial interpolation at $x=0$ for key reconstruction.
  4. ChaCha20-Poly1305 AEAD authenticated encryption and tamper detection.
  5. Anti-Replay temporal freshness window ($\pm 5.0\text{s}$).
  6. Replay attack rejection on Ground Station commands.
  7. Replay attack rejection on peer drone approvals.
  8. Autonomous performance metrics profiling per drone.
  9. Decentralized swarm consensus simulation round ($k=3, n=5$).
  10. Wire confidentiality: zero plaintext $(x, y)$ leakage in `ShareMessage.to_dict()`.
  11. Broadcast encryption: passive eavesdroppers unable to reconstruct secret.
  12. Active tampering: bit-flipped ciphertexts and incorrect keys rejected.

---

### 3.3 `up` — Launching the Live Multi-Container Swarm
```bash
# Default: 5 Drones, 256MB RAM per drone, 0.5 CPU cores
./docker_commands.sh up

# Custom: 10 Drones, 512MB RAM, 1.0 CPU cores
./docker_commands.sh up 10 512m 1.0
```

#### What Happens Step-by-Step on Docker:
1. **Bridge Mesh Creation:** Docker creates the virtual isolated bridge network `swarm-net`.
2. **Broker Startup (`pqc_mqtt_broker`):** Mosquitto broker starts on port `1883`, listening for swarm traffic.
3. **Ground Station Daemon (`pqc_ground_station`):**
   - Generates its Falcon-512 public/private keypair.
   - Broadcasts its Falcon public key over `swarm/registry`.
4. **Autonomous Drone Nodes (`pqc-drone-1` to `pqc-drone-N`):**
   - Each drone container starts [run_drone_node.py](file:///home/aj-shaer/Desktop/pqc/pqc-drone-swarm/run_drone_node.py).
   - Generates its own local Falcon-512 keypair.
   - Subscribes to `swarm/registry`, `swarm/commands`, `swarm/approvals`, and `swarm/shares`.
   - Broadcasts its public key over `swarm/registry`.
5. **Decentralized Share Assignment:** Ground Station assigns a Shamir share coordinate $(x, y)$ to each discovered drone.
6. **Command Dispatch:** Ground Station encrypts a mission payload with ChaCha20-Poly1305, signs the digest with Falcon-512, and broadcasts it on `swarm/commands`.
7. **Local Verification & Approval Gossip:** Each drone independently validates the Ground Station's signature and freshness, creates a signed `ApprovalMessage`, and gossips it on `swarm/approvals`.
8. **Threshold Trigger & Broadcast Share Exchange:** Once a drone collects $\ge k$ valid peer approvals, it releases its ChaCha20-Poly1305 encrypted share on `swarm/shares`.
9. **Decentralized Key Reconstruction & Execution:** Each drone accumulates $k$ shares, decrypts them via the Swarm Mesh Key ($K_{\text{mesh}}$), reconstructs the 256-bit symmetric mission key via Lagrange interpolation, decrypts the mission payload, and executes the mission command locally.
10. **Telemetry Harvester:** Drones publish their execution acknowledgments and sub-millisecond latency profiles to `swarm/telemetry`.

---

### 3.4 `logs` — Inspecting Swarm Consensus in Real-Time
```bash
./docker_commands.sh logs
```

#### Key Decentralized Protocol Log Signatures:
- **Ground Station Broadcast:**
  `[GS] 🔒 Encrypting (ChaCha20-Poly1305) and signing (Falcon-512) mission command...`
- **Drone GS Verification:**
  `[DRONE_1] ✅ Verified GS Falcon signature in 2.14ms. Broadcasting approval...`
- **Peer Approval Gossip:**
  `[DRONE_2] Verified approval from DRONE_1 in 1.85ms. (Total: 3/3)`
- **Broadcast Share Emission:**
  `[DRONE_1] 🎯 Threshold 3 met for approvals! Broadcasting Shamir share (🔒 AEAD Encrypted)...`
- **Local Reconstruction & Execution:**
  `[DRONE_2] ⚡ All threshold conditions satisfied! Reconstructing key and executing payload locally...`
  `[DRONE_2] 🏆 SUCCESS: Executed mission payload: {'action': 'MISSION_RECON', ...}`
- **Security Alert Telemetry (upon attack injection):**
  `[GS] 🚨 SECURITY ALERT from DRONE_3: SHARE_REJECTED (Invalid signature from peer DRONE_1)`

---

### 3.5 `attack` — Red-Team Security & Adversary Simulator
```bash
./docker_commands.sh attack [MODE] [DURATION] [TARGET]
```

The empirical testing harness executes six active and passive attack scenarios against the live cluster or standalone runtime:

#### Mode 1: `attack demo` — Comprehensive Multi-Vector Test Battery
```bash
./docker_commands.sh attack demo
```
- **Execution:** Automated standalone battery executing all 5 threat models against a $(3, 5)$ swarm in memory.
- **Empirical Output:**
  - Evaluates wire secrecy: computes Shannon entropy ($H \approx 6.88$ bits/byte) on encrypted shares.
  - Verifies rogue node AEAD tag validation failure across all peer shares.
  - Tests active bit-flipped ciphertext injection against multiple nodes ($D_1, D_2, D_3$).
  - Validates `AntiReplayFilter` state rejection on replayed share packets.
  - Confirms unauthorized Ground Station command rejection.

---

#### Mode 2: `attack eavesdrop` — Wire Sniffing & Cryptanalytic Entropy Analysis
```bash
./docker_commands.sh attack eavesdrop 30
```
- **Execution:** An unauthenticated container connects to `swarm-net` and sniffs `swarm/commands` and `swarm/shares`.
- **Empirical Output:**
  - Quantifies Shannon entropy of in-flight ciphertexts ($H \approx 7.99$ bits/byte).
  - Inspects network dictionaries: coordinates $x$ and $y$ are completely absent from wire packets.
  - Evaluates Lagrange reconstruction: demonstrates $0$ recoverable coordinate points and $0 / 256$ leaked mission key bits under the Dolev-Yao wire sniffer model.

---

#### Mode 3: `attack wrong-key` — Rogue Node Key Mismatch & Injection Defense
```bash
./docker_commands.sh attack wrong-key 30
```
- **Execution:** Injects a rogue drone container into `swarm-net` with an invalid `SWARM_MESH_KEY` (`0000...`).
- **Empirical Output:**
  - **Ingress Isolation:** When honest drones broadcast shares, the rogue node attempts decryption; ChaCha20-Poly1305 raises an authentication tag failure (`InvalidTag`), preventing share accumulation.
  - **Egress Rejection:** The rogue node broadcasts a forged share onto `swarm/shares`. Receiving Docker drone nodes verify with their honest mesh key, detect the authentication failure, drop the packet, and broadcast `SECURITY_ALERT` telemetry.

---

#### Mode 4: `attack tamper` — Active MitM Ciphertext Modification
```bash
# Tamper with shares from any broadcasting drone
./docker_commands.sh attack tamper 30 all

# Tamper specifically with shares from Drone 2
./docker_commands.sh attack tamper 30 DRONE_2
```
- **Execution:** Intercepts legitimate in-flight share broadcasts on `swarm/shares`, flips bits in `ciphertext_hex`, and re-injects the corrupted packet into the mesh.
- **Empirical Output:**
  - Receiving drone containers invoke `receive_share()` and drop the packet at two cryptographic layers:
    1. **Falcon-512 Digital Signature:** Digest mismatch over altered ciphertext bytes.
    2. **Poly1305 AEAD MAC Tag:** Decryption raises `InvalidTag`.
  - Recipient containers emit `SECURITY_ALERT` events (`alert_type: SHARE_REJECTED`) on `swarm/telemetry`, captured and confirmed by the attack harness.

---

#### Mode 5: `attack replay` — Temporal Replay Attack against Sliding Window
```bash
./docker_commands.sh attack replay 30
```
- **Execution:** Intercepts an authentic, validly signed packet, waits for honest nodes to process it, and re-broadcasts the exact original packet onto the mesh.
- **Empirical Output:**
  - Packet possesses a 100% valid Falcon-512 signature and valid Poly1305 MAC tag.
  - Honest drone nodes query their local `AntiReplayFilter` state:
    `Replay detected: identifier 'SHARE:cmd-replay:DRONE_1' already processed`
  - Duplicate is dropped; recipient nodes report `SECURITY_ALERT` telemetry; zero redundant executions occur.

---

#### Mode 6: `attack rogue-gs` — Unauthorized Command Forgery
```bash
./docker_commands.sh attack rogue-gs 20
```
- **Execution:** Broadcasts a forged mission command onto `swarm/commands` signed with an unrecognized Falcon-512 keypair.
- **Empirical Output:**
  - Drones verify against the pinned `gs_public_key` in their trust registry:
    `Invalid Falcon-512 GS signature`
  - Rejection is logged and reported via `SECURITY_ALERT` telemetry; zero approvals or shares are emitted by the swarm.

---

### 3.6 `down` — Swarm Teardown
```bash
./docker_commands.sh down
```
- Gracefully stops all container processes (`SIGTERM` handling).
- Removes container namespaces and the virtual bridge network `swarm-net`.
- Zero residual artifacts left on the host.
