import json
import os
import sys
import uuid
import time
import hashlib
import secrets
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

script_dir = os.path.dirname(os.path.abspath(__file__))
repo_root = os.path.abspath(os.path.join(script_dir, "..", ".."))
falcon_candidate = os.getenv("FALCON_PATH") or os.path.join(repo_root, "falcon_py")
if os.path.isdir(falcon_candidate):
    sys.path.insert(0, falcon_candidate)

print("using falcon path:", falcon_candidate)

from falcon import Falcon

# module-level Falcon model used by classes below
model = Falcon(512)


# Utility functions
def deterministic_serialize(command):
    return json.dumps(command, sort_keys=True).encode()

def hash_command(command):
    return hashlib.sha256(deterministic_serialize(command)).digest()

# Command model
@dataclass
class Command:
    command_id: str
    timestamp: float
    nonce: bytes
    aad: bytes
    ciphertext: bytes
    gs_signature: bytes = None
    approvals: dict = field(default_factory=dict)

    # timing fields
    gs_sign_time: float = None
    approval_times: dict = field(default_factory=dict)
    verify_times: dict = field(default_factory=dict)
    start_time: float = None
    end_time: float = None

    def serialize_for_signing(self):
        return json.dumps({
            "command_id": self.command_id,
            "timestamp": self.timestamp,
            "nonce": self.nonce.hex(),
            "aad": self.aad.hex(),
            "ciphertext": self.ciphertext.hex()
        }, sort_keys=True).encode()
    
    def digest(self):
        return hashlib.sha256(self.serialize_for_signing()).digest()
    
# Trust Registry
class TrustRegistry:
    def __init__(self):
        self.registry = {}

    def register_drone(self, pseudo_id, public_key):
        self.registry[pseudo_id] = public_key
    
    def get_public_key(self, pseudo_id):
        return self.registry.get(pseudo_id)
    
    def is_trusted(self, pseudo_id):
        return pseudo_id in self.registry
    
# Drone node
class DroneNode:
    def __init__(self, pseudo_id, trust_registry, swarm_key):
        self.pseudo_id = pseudo_id
        t0 = time.perf_counter()
        self.private_key, self.public_key = model.keygen()
        t1 = time.perf_counter()
        self.keygen_time = t1 - t0
        print(f"[DRONE {pseudo_id}] keygen time: {self.keygen_time:.6f}s")
        self.trust_registry = trust_registry
        self.swarm_key = swarm_key

        trust_registry.register_drone(pseudo_id, self.public_key)
    
    def verify_gs_command(self, command, gs_public_key):
        try:
            t0 = time.perf_counter()
            model.verify(gs_public_key, command.digest(), command.gs_signature)
            t1 = time.perf_counter()
            elapsed = t1 - t0
            command.verify_times[self.pseudo_id] = elapsed
            print(f"[DRONE {self.pseudo_id}] verified GS signature in {elapsed:.6f}s")
            return True
        except Exception:
            return False
        
    def approve_command(self, command):
        t0 = time.perf_counter()
        signature = model.sign(self.private_key, command.digest())
        t1 = time.perf_counter()
        elapsed = t1 - t0
        command.approvals[self.pseudo_id] = signature
        command.approval_times[self.pseudo_id] = elapsed
        print(f"[DRONE {self.pseudo_id}] approved command (sign time {elapsed:.6f}s)")

# Ground Station
class GroundStation:
    def __init__(self, swarm_key):
        t0 = time.perf_counter()
        self.private_key, self.public_key = model.keygen()
        t1 = time.perf_counter()
        self.keygen_time = t1 - t0
        print(f"[GROUND STATION] keygen time: {self.keygen_time:.6f}s")
        self.swarm_key = swarm_key

    def create_command(self, command_dict):

        start = time.perf_counter()

        chacha = ChaCha20Poly1305(self.swarm_key)
        nonce = os.urandom(12)
        aad = b"swarm_command"
        plaintext = json.dumps(command_dict).encode()
        ciphertext = chacha.encrypt(nonce, plaintext, aad)

        command = Command(
            command_id=str(uuid.uuid4()),
            timestamp=time.time(),
            nonce=nonce,
            aad=aad,
            ciphertext=ciphertext
        )

        command.start_time = start

        t0 = time.perf_counter()
        signature = model.sign(self.private_key, command.digest())
        t1 = time.perf_counter()
        command.gs_signature = signature
        command.gs_sign_time = t1 - t0
        print(f"[GROUND STATION] command created and signed (sign time {command.gs_sign_time:.6f}s)")
        return command
    
# Threshold approval
class ThresholdEngine:
    def __init__(self, trust_registry, threshold_k):
        self.threshold_k = threshold_k
        self.trust_registry = trust_registry

    def check(self, command):
        valid = 0
        for drone_id, signature in command.approvals.items():
            if not self.trust_registry.is_trusted(drone_id):
                continue

            public_key = self.trust_registry.get_public_key(drone_id)
            try:
                t0 = time.perf_counter()
                model.verify(public_key, command.digest(), signature)
                t1 = time.perf_counter()
                elapsed = t1 - t0
                command.verify_times[f"approval_{drone_id}"] = elapsed
                print(f"[AUTH] verified approval from {drone_id} in {elapsed:.6f}s")
                valid += 1
            except:
                pass
        print(f"[AUTH] valid approvals = {valid}")

        return valid >= self.threshold_k
    
# Secure Execution Engine
class SecureExecutionEngine:
    def __init__(self, swarm_key):
        self.swarm_key = swarm_key

    def execute(self, command):
        chacha = ChaCha20Poly1305(self.swarm_key)
        try:
            plaintext = chacha.decrypt(command.nonce, command.ciphertext, command.aad)
            payload = json.loads(plaintext.decode())
            
            command.end_time = time.perf_counter()
            latency = command.end_time - command.start_time

            print(f"\n[EXECUTION] Command executed: {payload}")
            print(f"\n[EXECUTION] Total latency from creation to execution: {latency:.6f}s")

        except Exception as e:
            print(f"[EXECUTION] Decryption failed: {str(e)}")

# Simulation
def main():

    print("\n--- FALCON BOOT ---\n")

    print("\n--- SWARM SYSTEM BOOT ---\n")

    swarm_key = ChaCha20Poly1305.generate_key()

    trust_registry = TrustRegistry()

    # create drones
    d1 = DroneNode("PID_A", trust_registry, swarm_key)
    d2 = DroneNode("PID_B", trust_registry, swarm_key)
    d3 = DroneNode("PID_C", trust_registry, swarm_key)

    drones = [d1, d2, d3]

    # ground station
    gs = GroundStation(swarm_key)

    payload = {
        "action": "MOVE",
        "target": "ZONE_A",
        "speed": 5
    }

    command = gs.create_command(payload)

    print("\n--- DRONES VERIFY COMMAND ---\n")

    for drone in drones:

        if drone.verify_gs_command(command, gs.public_key):
            drone.approve_command(command)

    # threshold engine
    threshold = ThresholdEngine(trust_registry, threshold_k=2)

    print("\n--- THRESHOLD CHECK ---\n")

    if threshold.check(command):

        executor = SecureExecutionEngine(swarm_key)
        executor.execute(command)

    else:
        print("Authorization failed")


if __name__ == "__main__":
    main()