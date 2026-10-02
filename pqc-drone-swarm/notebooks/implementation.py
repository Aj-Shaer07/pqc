from dataclasses import field, dataclass
import hashlib
import json, secrets, random, os, time, sys

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

script_dir = os.path.dirname(os.path.abspath(__file__))
repo_root = os.path.abspath(os.path.join(script_dir, "..", ".."))
falcon_candidate = os.getenv("FALCON_PATH") or os.path.join(repo_root, "falcon_py")
if os.path.isdir(falcon_candidate):
    sys.path.insert(0, falcon_candidate)

print("using falcon path:", falcon_candidate)

from falcon import Falcon

PRIME = 2**521 - 1
model = Falcon(512)

# Shamir Secret Sharing
def evaluate_polynomial(x, coefficients):
    result = 0
    for p, coeff in enumerate(coefficients):
        term = (coeff * pow(x, p, PRIME)) % PRIME
        result = (result + term) % PRIME
    return result

def generate_shares(secret, threshold, num_shares):
    coefficients= [secret]

    for _ in range(threshold - 1):
        coefficients.append(random.randrange(1, PRIME))
    
    shares = []

    for x in range(1, num_shares+1):
        share = evaluate_polynomial(x, coefficients)
        shares.append((x,share))
    print(f"Generated shares: {shares}")
    return shares

def reconstruct_secret(shares):
    secret = 0

    for j, (xj, yj) in enumerate(shares):
        num = 1
        den = 1

        for m, (xm, _) in enumerate(shares):
            if m != j:
                num = (num * (-xm % PRIME)) % PRIME
                den = (den * ((xj - xm) % PRIME)) % PRIME

        lag = (num * pow(den, -1, PRIME)) % PRIME
        secret = (secret + (yj * lag) % PRIME) % PRIME
    return secret

#Command Class
@dataclass
class Command:
    command_id: str
    timestamp: float
    nonce: bytes
    aad: bytes
    ciphertext: bytes
    
    gs_signature: bytes = None
    approvals: dict = field(default_factory=dict)

    #timing
    gs_sign_time: float = None
    drone_verify_gs_times: dict = field(default_factory=dict)
    approval_times: dict = field(default_factory=dict)
    te_verify_approval_times: dict = field(default_factory=dict)

    def serialize_for_signing(self):
        data = {
            "command_id": self.command_id,
            "timestamp": self.timestamp,
            "nonce": self.nonce.hex(),
            "aad": self.aad.hex(),
            "ciphertext": self.ciphertext.hex()
        }
        return json.dumps(data, sort_keys=True).encode()
    
    def digest(self):
        return hashlib.sha256(self.serialize_for_signing()).digest()

#Trust Registry
class TrustRegistry:
    def __init__(self):
        self.registry = {}

    def register_drone(self, pseudo_id, public_key):
        self.registry[pseudo_id] = public_key
    
    def get_public_key(self, pseudo_id):
        return self.registry.get(pseudo_id)
    
    def is_trusted(self, pseudo_id):
        return pseudo_id in self.registry

# Drone class
class Drone:
    def __init__(self, drone_id, share, trust_registry):
        self.drone_id = drone_id
        self.share = share
        self.trust_registry = trust_registry

        start = time.perf_counter()
        self.private_key, self.public_key = model.keygen()
        end = time.perf_counter()
        self.keygen_time = end - start
        print(f"[DRONE {drone_id}] Keygen time: {self.keygen_time:.6f}s")       
        trust_registry.register_drone(drone_id, self.public_key)

    def provide_share(self):
        print(f"Drone {self.drone_id} providing share: {self.share}")
        return self.share

    def verify_gs_command(self, command, gs_public_key):
        digest = command.digest()

        start = time.perf_counter()
        try:
            model.verify(gs_public_key, digest, command.gs_signature)
            valid = True
        except:
            valid = False
        end = time.perf_counter()
        elapsed = end - start
        command.drone_verify_gs_times[self.drone_id] = elapsed
        print(f"[DRONE {self.drone_id}] Verified GS signature in {elapsed:.6f}s")
        return valid
    
    def approve_command(self, command):
        digest = command.digest()

        start = time.perf_counter()
        signature = model.sign(self.private_key, digest)
        end = time.perf_counter()
        elapsed = end - start
        
        command.approval_times[self.drone_id] = elapsed
        # store the approval signature on the command so the threshold engine can verify it
        command.approvals[self.drone_id] = signature
        print(f"[DRONE {self.drone_id}] Approved command in {elapsed:.6f}s")
        return signature
    
# Ground Station
class GroundStation:
    def __init__(self):
        start = time.perf_counter()
        self.private_key, self.public_key = model.keygen()
        end = time.perf_counter()
        self.keygen_time = end - start
        print(f"[GROUND STATION] Keygen time: {self.keygen_time:.6f}s")

    def create_command(self, payload, mission_key):
        chacha = ChaCha20Poly1305(mission_key)
        
        nonce = secrets.token_bytes(12)
        aad = b"swarm_command"

        plaintext = json.dumps(payload).encode()
        ciphertext = chacha.encrypt(nonce, plaintext, aad)

        command = Command(
            command_id = secrets.token_hex(8),
            timestamp = time.time(),
            nonce = nonce,
            aad = aad,
            ciphertext = ciphertext
        )
        start = time.perf_counter()
        command.gs_signature = model.sign(self.private_key, command.digest())
        end = time.perf_counter()
        command.gs_sign_time = end - start
        print(f"[GROUND STATION] Created command with GS signature in {command.gs_sign_time:.6f}s")
        return command
    
#Treshold Engine
class ThresholdEngine:
    def __init__(self, trust_registry, drones, threshold):
        self.trust_registry = trust_registry
        self.drones = drones
        self.threshold = threshold
    
    def check(self, command):
        valid_drones=[]
        for drone_id, signature in command.approvals.items():
            if not self.trust_registry.is_trusted(drone_id):
                print(f"[THRESHOLD ENGINE] Drone {drone_id} is not trusted")
                continue
            
            pub = self.trust_registry.get_public_key(drone_id)

            start = time.perf_counter()
            try:
                model.verify(pub, command.digest(), signature)
                valid_drones.append(drone_id)
            except:
                print(f"[THRESHOLD ENGINE] Invalid signature from drone {drone_id}")
                continue
            end = time.perf_counter()
            elapsed = end - start
            command.te_verify_approval_times[drone_id] = elapsed
            print(f"[THRESHOLD ENGINE] Verified approval from {drone_id} in {elapsed:.6f}s")
        print(f"[THRESHOLD ENGINE] Valid approvals: {valid_drones}")
        return valid_drones
    
#Secure Execution Engine
class SecureExecutionEngine:
    def execute(self, command, mission_key):
        chacha = ChaCha20Poly1305(mission_key)
    
        try:
            plaintext = chacha.decrypt(command.nonce, command.ciphertext, command.aad)
            payload = json.loads(plaintext.decode())
            print(f"[SECURE EXECUTION ENGINE] Command executed with payload: {payload}")
            return payload
        except Exception as e:
            print(f"[SECURE EXECUTION ENGINE] Failed to execute command: {e}")
            return None

def run_simulation(k=3, n=5):
    print(f"\n{'='*20} RUNNING SIMULATION (k={k}, n={n}) {'='*20}")
    trust_registry = TrustRegistry()

    mission_key = ChaCha20Poly1305.generate_key()
    mission_key_int = int.from_bytes(mission_key, byteorder='big')

    #TSS
    shares = generate_shares(mission_key_int, k, n)
    drones = []
    for i, share in enumerate(shares):
        drone = Drone(f"PID_{i+1}", share, trust_registry)
        drones.append(drone)

    gs = GroundStation()
    payload = {"action": "takeoff", "altitude": 100}
    command = gs.create_command(payload, mission_key)

    for drone in drones:
        if drone.verify_gs_command(command, gs.public_key):
            drone.approve_command(command)

    print("\n=== Threshold Engine Checking Approvals ===\n")
    threshold_engine = ThresholdEngine(trust_registry, drones, k)
    valid_drones = threshold_engine.check(command)

    if len(valid_drones) >= k:
        print("\n=== Reconstructing Mission Key ===\n")
        # Randomly choose how many of the *valid* drones actually provide their shares
        num_providers = random.randrange(0, len(valid_drones) + 1)
        print(f"Choosing {num_providers} drones to provide shares")
        collected_shares = []
        c = 0
        for drone in drones:
            if drone.drone_id in valid_drones and c < num_providers:
                collected_shares.append(drone.provide_share())
                c += 1

        if len(collected_shares) >= k:
            reconstructed_key_int = reconstruct_secret(collected_shares)
            try:
                reconstructed_key = reconstructed_key_int.to_bytes(32, byteorder='big')
            except OverflowError:
                print("[ERROR] Reconstructed integer too large for 32 bytes — aborting execution")
                return

            print(f"Reconstructed mission key: {reconstructed_key.hex()}")

            print("\n=== Secure Execution Engine Executing Command ===\n")
            secure_engine = SecureExecutionEngine()
            secure_engine.execute(command, reconstructed_key)
        else:
            print(f"Not enough shares provided for reconstruction. Required: {k}, Provided: {len(collected_shares)}")
            print("[THRESHOLD ENGINE] Command execution denied due to insufficient share providers")
    else:
        print(f"Not enough valid approvals to execute command. Required: {k}, Got: {len(valid_drones)}")
        print("[THRESHOLD ENGINE] Command execution denied due to insufficient valid approvals\n")

    drone_keygen = [d.keygen_time for d in drones]
    drone_verify = list(command.drone_verify_gs_times.values())
    drone_approve = list(command.approval_times.values())
    te_verify = list(command.te_verify_approval_times.values())
    
    def safe_avg(times): return sum(times)/len(times) if times else 0
    def safe_min(times): return min(times) if times else 0
    def safe_max(times): return max(times) if times else 0

    return {
        'k': k,
        'n': n,
        'gs_keygen': gs.keygen_time,
        'gs_sign': command.gs_sign_time,
        'drone_keygen_avg': safe_avg(drone_keygen),
        'drone_keygen_min': safe_min(drone_keygen),
        'drone_keygen_max': safe_max(drone_keygen),
        'drone_verify_avg': safe_avg(drone_verify),
        'drone_verify_min': safe_min(drone_verify),
        'drone_verify_max': safe_max(drone_verify),
        'drone_approve_avg': safe_avg(drone_approve),
        'drone_approve_min': safe_min(drone_approve),
        'drone_approve_max': safe_max(drone_approve),
        'te_verify_avg': safe_avg(te_verify),
        'te_verify_min': safe_min(te_verify),
        'te_verify_max': safe_max(te_verify),
    }

def main():
    import csv
    
    # Define the simulation configurations (k, n)
    configurations = [
        (3, 5),
        (5, 10),
        (10, 20),
        (25, 50)
    ]
    num_runs = 10
    
    all_results = []
    for k, n in configurations:
        print(f"\n{'*'*40}\nStarting config k={k}, n={n} for {num_runs} iterations\n{'*'*40}")
        metrics = {
            'gs_keygen': [], 'gs_sign': [],
            'drone_keygen_avg': [], 'drone_verify_avg': [],
            'drone_approve_avg': [], 'te_verify_avg': []
        }
        for i in range(num_runs):
            try:
                res = run_simulation(k, n)
                metrics['gs_keygen'].append(res['gs_keygen'])
                metrics['gs_sign'].append(res['gs_sign'])
                metrics['drone_keygen_avg'].append(res['drone_keygen_avg'])
                metrics['drone_verify_avg'].append(res['drone_verify_avg'])
                metrics['drone_approve_avg'].append(res['drone_approve_avg'])
                metrics['te_verify_avg'].append(res['te_verify_avg'])
            except Exception as e:
                print(f"Simulation failed for k={k}, n={n} on run {i}: {e}")
        
        if not metrics['gs_keygen']:
            continue
            
        def mean(val_list): return sum(val_list)/len(val_list) if val_list else 0
        
        all_results.append({
            'k': k,
            'n': n,
            'runs': len(metrics['gs_keygen']),
            'gs_keygen_mean': mean(metrics['gs_keygen']),
            'gs_sign_mean': mean(metrics['gs_sign']),
            'drone_keygen_mean': mean(metrics['drone_keygen_avg']),
            'drone_verify_mean': mean(metrics['drone_verify_avg']),
            'drone_approve_mean': mean(metrics['drone_approve_avg']),
            'te_verify_mean': mean(metrics['te_verify_avg'])
        })
            
    csv_filename = os.path.join(script_dir, 'multi_simulation_results.csv')
    try:
        with open(csv_filename, 'w', newline='') as f:
            if not all_results:
                return
            writer = csv.DictWriter(f, fieldnames=all_results[0].keys())
            writer.writeheader()
            for row in all_results:
                writer.writerow(row)
        print(f"\n[SUCCESS] Saved 10-run averaged results to {csv_filename}")
    except Exception as e:
        print(f"\n[ERROR] Failed to save CSV: {e}")

if __name__=="__main__":
    main()