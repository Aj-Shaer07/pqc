import os
import sys
import unittest

# Ensure src/ is automatically added to sys.path so tests work out-of-the-box
_test_dir = os.path.dirname(os.path.abspath(__file__))
_src_dir = os.path.abspath(os.path.join(_test_dir, "..", "src"))
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

from pqc_swarm.crypto.falcon import FalconSigner
from pqc_swarm.crypto.sss import generate_shares, reconstruct_secret, PRIME
from pqc_swarm.crypto.aead import generate_mission_key, encrypt_payload, decrypt_payload
from pqc_swarm.models.messages import CommandMessage, ApprovalMessage, ShareMessage
from pqc_swarm.models.registry import TrustRegistry
from pqc_swarm.sim.in_memory_sim import run_decentralized_simulation

class TestPQCDroneSwarm(unittest.TestCase):

    def test_falcon_sign_and_verify(self):
        signer = FalconSigner(512)
        sk, pk = signer.keygen()
        message = b"Swarm Alert: Mission Authorized"
        signature = signer.sign(sk, message)
        self.assertTrue(signer.verify(pk, message, signature))
        # Tampered message must fail
        self.assertFalse(signer.verify(pk, b"Tampered Message", signature))

    def test_shamir_secret_sharing_threshold(self):
        secret = 1234567890987654321
        threshold = 3
        num_shares = 5

        shares = generate_shares(secret, threshold, num_shares)
        self.assertEqual(len(shares), num_shares)

        # Any 3 shares reconstruct correctly
        self.assertEqual(reconstruct_secret(shares[:3]), secret)
        self.assertEqual(reconstruct_secret([shares[0], shares[2], shares[4]]), secret)

        # Invalid threshold count (e.g. 2 shares) must not yield the secret
        self.assertNotEqual(reconstruct_secret(shares[:2]), secret)

    def test_aead_encrypt_decrypt(self):
        key = generate_mission_key()
        payload = {"target": "Base-Alpha", "speed_mps": 15.5}
        nonce, ciphertext = encrypt_payload(key, payload)

        decrypted = decrypt_payload(key, nonce, ciphertext)
        self.assertEqual(decrypted, payload)

    def test_trust_registry_revocation(self):
        registry = TrustRegistry()
        drone_id = "DRONE_X"
        fake_pk = b"fake_public_key_bytes"

        registry.register_drone(drone_id, fake_pk)
        self.assertTrue(registry.is_trusted(drone_id))

        registry.revoke_drone(drone_id)
        self.assertFalse(registry.is_trusted(drone_id))
        self.assertIsNone(registry.get_public_key(drone_id))

    def test_decentralized_swarm_simulation_round(self):
        res = run_decentralized_simulation(k=3, n=5)
        self.assertEqual(res["k"], 3)
        self.assertEqual(res["n"], 5)
        self.assertEqual(res["executed_count"], 5)  # All 5 drones successfully verified & executed
        self.assertGreater(res["gs_sign"], 0)
        self.assertGreater(res["drone_verify_avg"], 0)
        self.assertGreater(res["drone_approve_avg"], 0)


if __name__ == "__main__":
    unittest.main()
