# Journal Paper Implementation Plan

This document outlines the architectural roadmap for upgrading the current PQC Drone Swarm Proof of Concept (PoC) into a fully distributed, formally verified system suitable for a journal publication.

## Proposed Changes

We will break the implementation into four distinct phases to ensure stability and correctness at each step.

### Phase 1: Code Decoupling & Networking (The Application Layer)
Currently, the simulation runs sequentially in memory. We need to decouple the components so they can run over a network in a truly decentralized manner.
*   **Kill the Centralized Engine:** The `ThresholdEngine` should not be a standalone centralized entity. Instead, the threshold logic will be embedded *inside* every drone.
*   **Introduce MQTT / Gossip Protocol:** Use the `paho-mqtt` library to act as the wireless communication layer.
    *   The Ground Station publishes commands to a `swarm/commands` topic.
    *   Drones independently verify the command and broadcast their approvals to a `swarm/approvals` peer-to-peer topic.
    *   Each drone independently counts to $k$ approvals. Once a drone sees $k$ valid approvals, it executes the command locally.

### Phase 2: Dockerization (The Hardware Simulation Layer)
To achieve true parallelism and isolate the nodes to mimic physical hardware:
*   **Dockerfile:** Create a base image containing Python 3.14, `cryptography`, and your `falcon_py` module.
*   **Docker Compose:** Create a `docker-compose.yml` that automatically spins up:
    *   1x Eclipse Mosquitto (MQTT Broker simulating the mesh network)
    *   1x Ground Station Container
    *   $N$x Drone Containers (acting autonomously)

### Phase 3: Protocol & Security Hardening (Swarm Resilience)
Before running formal verification, the protocol must address physical swarm realities:
*   **Replay Attack Defense:** Update the drones to explicitly validate the `timestamp` (e.g., reject commands older than 5 seconds) and cache the `nonce` to reject duplicates.
*   **Ground Station Compromise:** To prevent a single compromised GS from hijacking the swarm, commands must be constrained by autonomous drone policies (e.g., drones reject commands that violate geofences or collision physics, regardless of GS signature validity). Alternatively, implement a multi-signature requirement (e.g., requires $2$ GS operators to sign).
*   **Dynamic Membership (Drone Swapping):** Implement an update mechanism for the `TrustRegistry`. If a drone is compromised or needs swapping, the GS broadcasts a revocation list. The new drone is onboarded with a fresh share, utilizing Proactive Secret Sharing (PSS) principles without changing the master `mission_key`.
*   **Geofencing & Node Drop-outs:** The beauty of the $k$-out-of-$n$ threshold is built-in fault tolerance. If a drone leaves the geofence or loses connectivity, it stops broadcasting approvals. As long as the remaining active swarm >= $k$, the mission continues seamlessly. If active drones drop below $k$, the swarm triggers an autonomous fail-safe (e.g., Return-to-Launch).
*   **Broadcast Encryption (Eavesdropping Protection):** Implement TLS or a pre-shared mesh network key over the MQTT layer to ensure an attacker capturing packets cannot reconstruct the Secret Shares or view the encrypted command payloads.

### Phase 4: Formal Security Verification
Alongside the Python implementation, we will create the formal mathematical models for the paper's security analysis section.
*   **BAN Logic Formulation:** Draft a markdown document laying out the idealizations, assumptions, and logical derivations proving mutual authentication and freshness.
*   **Automated Verification:** Write the protocol into a ProVerif (`.pv`) or Tamarin (`.spthy`) model file. We will simulate an attacker (Dolev-Yao model) attempting to compromise the GS, inject fake approvals, or capture a drone to mathematically prove the protocol's resilience.

## Verification Plan
1. **Automated Tests:** The Docker environment will output latency, keygen, and verification times (similar to our previous CSV), but this time reflecting *real* network latency and parallel CPU execution.
2. **Formal Verification:** Running ProVerif/Tamarin should yield a terminal output explicitly stating `RESULT: secrecy is true` and `RESULT: authentication is true`.
