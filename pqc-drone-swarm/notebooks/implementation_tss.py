import random

PRIME = 2**127-1

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

class Drone:
    def __init__(self, drone_id, share):
        self.drone_id = drone_id
        self.share = share
    
    def provide_share(self):
        print(f"Drone {self.drone_id} providing share: {self.share}")
        return self.share
    
def main():
    secret = random.randint(1, PRIME-1)
    original_secret = secret
    print(f"Original secret: {original_secret}")

    threshold = 3
    num_drones = 5

    print(f"Splitting secret into {num_drones} shares with threshold {threshold}...")

    share = generate_shares(secret, threshold, num_drones)
    drones = []

    for i, share in enumerate(share):
        drone = Drone(f"PID_{i+1}", share)
        drones.append(drone)
        print(f"[INIT] Drone PID_{i+1} received share {share}")

    print("\n--- RECONSTRUCTION PHASE ---\n")
    collected_shares = []

    n = random.randrange(0, num_drones)
    # Choose at least 'threshold' drones so reconstruction test is meaningful
    n = random.randrange(0, num_drones+1)
    print(f"Choosing {n} drones to provide shares")
    c = 0
    for i, drone in enumerate(drones):
        if c < n:
            collected_shares.append(drone.provide_share())
            c += 1
    recovered_secret = reconstruct_secret(collected_shares)
    print(f"Recovered secret: {recovered_secret}")
    if recovered_secret == secret:
        print(f"SUCCESS: Secret reconstructed with {n} shares")
    else:
        print("ERROR: Reconstruction failed")


if __name__ == "__main__":
    main()


