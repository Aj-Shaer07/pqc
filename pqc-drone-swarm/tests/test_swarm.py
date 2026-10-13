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

from pqc_swarm.crypto.anti_replay import AntiReplayFilter
from pqc_swarm.nodes.drone import DroneNode
from pqc_swarm.nodes.ground_station import GroundStationNode
import time

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

    def test_anti_replay_filter_freshness_and_replay(self):
        filt = AntiReplayFilter(window_seconds=5.0)
        now = 1000.0

        # 1. Fresh message accepted
        ok, reason = filt.validate_and_record("msg-1", 1000.0, current_time=now)
        self.assertTrue(ok)
        self.assertEqual(reason, "OK")

        # 2. Replayed identifier rejected
        ok, reason = filt.validate_and_record("msg-1", 1001.0, current_time=now)
        self.assertFalse(ok)
        self.assertIn("Replay detected", reason)

        # 3. Stale / expired message rejected (> 5s in the past)
        ok, reason = filt.validate_and_record("msg-2", 994.0, current_time=now)
        self.assertFalse(ok)
        self.assertIn("expired / stale", reason)

        # 4. Future timestamp rejected (> 5s in future)
        ok, reason = filt.validate_and_record("msg-3", 1006.0, current_time=now)
        self.assertFalse(ok)
        self.assertIn("future", reason)

        # 5. Cleanup removes ancient identifiers
        pruned = filt.cleanup(current_time=now + 20.0)
        self.assertEqual(pruned, 1)
        self.assertEqual(filt.tracked_count, 0)

    def test_drone_node_anti_replay_rejection(self):
        registry = TrustRegistry()
        gs = GroundStationNode()
        registry.set_gs_public_key(gs.public_key)

        drone = DroneNode(
            drone_id="DRONE_1",
            share=(1, 100),
            threshold=2,
            trust_registry=registry,
            freshness_window_sec=5.0,
        )

        mission_key = generate_mission_key()
        cmd, _ = gs.create_command({"action": "PATROL"}, mission_key)

        # First verification succeeds
        valid, _ = drone.verify_gs_command(cmd)
        self.assertTrue(valid)

        # Replayed command must be rejected
        replay_valid, _ = drone.verify_gs_command(cmd)
        self.assertFalse(replay_valid)
        self.assertIn("Replay detected", drone.last_rejection_reason)

        # Stale command must be rejected
        stale_cmd = CommandMessage(
            command_id="stale_cmd_1",
            timestamp=time.time() - 30.0,  # 30 seconds ago
            nonce_hex="aabbccdd",
            aad_hex="00",
            ciphertext_hex="112233",
        )
        sig = gs.signer.sign(gs.private_key, stale_cmd.digest())
        stale_cmd = stale_cmd.with_signature(sig)

        stale_valid, _ = drone.verify_gs_command(stale_cmd)
        self.assertFalse(stale_valid)
        self.assertIn("expired / stale", drone.last_rejection_reason)

    def test_drone_node_peer_approval_replay_rejection(self):
        registry = TrustRegistry()
        gs = GroundStationNode()
        registry.set_gs_public_key(gs.public_key)

        d1 = DroneNode("DRONE_1", share=(1, 10), threshold=2, trust_registry=registry)
        d2 = DroneNode("DRONE_2", share=(2, 20), threshold=2, trust_registry=registry)

        registry.register_drone(d1.drone_id, d1.public_key)
        registry.register_drone(d2.drone_id, d2.public_key)

        mission_key = generate_mission_key()
        cmd, _ = gs.create_command({"action": "TAKEOFF"}, mission_key)

        d1.verify_gs_command(cmd)
        d2.verify_gs_command(cmd)

        app1, _ = d1.create_approval(cmd.command_id)

        # First acceptance
        ok, _ = d2.process_peer_approval(app1)
        self.assertTrue(ok)

        # Replay must be rejected
        ok_replay, _ = d2.process_peer_approval(app1)
        self.assertFalse(ok_replay)
        self.assertIn("Replay detected", d2.last_rejection_reason)

    def test_drone_performance_metrics_profiling(self):
        registry = TrustRegistry()
        gs = GroundStationNode()
        registry.set_gs_public_key(gs.public_key)

        mission_key = generate_mission_key()
        mission_key_int = int.from_bytes(mission_key, byteorder="big")
        shares = generate_shares(mission_key_int, threshold=2, num_shares=2)

        d1 = DroneNode("DRONE_1", share=shares[0], threshold=2, trust_registry=registry)
        d2 = DroneNode("DRONE_2", share=shares[1], threshold=2, trust_registry=registry)

        registry.register_drone(d1.drone_id, d1.public_key)
        registry.register_drone(d2.drone_id, d2.public_key)

        payload = {"action": "HOVER", "alt": 50}
        cmd, _ = gs.create_command(payload, mission_key)

        d1.verify_gs_command(cmd)
        d2.verify_gs_command(cmd)

        app1, _ = d1.create_approval(cmd.command_id)
        app2, _ = d2.create_approval(cmd.command_id)

        d1.process_peer_approval(app2)
        d2.process_peer_approval(app1)

        s2 = d2.provide_share(cmd.command_id)
        d1.receive_share(s2)

        self.assertTrue(d1.can_execute(cmd.command_id))
        result = d1.execute_command(cmd.command_id)
        self.assertEqual(result, payload)

        metrics = d1.get_metrics(cmd.command_id)
        self.assertIsNotNone(metrics)
        self.assertGreater(metrics["gs_verify_time_ms"], 0)
        self.assertGreater(metrics["reconstruct_time_ms"], 0)
        self.assertGreater(metrics["decrypt_time_ms"], 0)
        self.assertGreater(metrics["total_consensus_time_ms"], 0)
        self.assertEqual(metrics["approvals_count"], 2)

    def test_decentralized_swarm_simulation_round(self):
        # Test with broadcast encryption active
        res_enc = run_decentralized_simulation(k=3, n=5, use_encrypted_shares=True)
        self.assertEqual(res_enc["k"], 3)
        self.assertEqual(res_enc["n"], 5)
        self.assertEqual(res_enc["executed_count"], 5)
        self.assertGreater(res_enc["gs_sign"], 0)
        self.assertGreater(res_enc["drone_verify_avg"], 0)
        self.assertGreater(res_enc["drone_approve_avg"], 0)

        # Test plaintext backward compatibility
        res_plain = run_decentralized_simulation(k=3, n=5, use_encrypted_shares=False)
        self.assertEqual(res_plain["executed_count"], 5)

    def test_encrypted_share_message_wire_format(self):
        """Verify that encrypted ShareMessage never exposes plaintext (x, y) on the wire."""
        mesh_key = generate_mission_key()
        registry = TrustRegistry()
        d = DroneNode("DRONE_1", share=(5, 99999), threshold=2, trust_registry=registry, mesh_key=mesh_key)

        share_msg = d.provide_share("cmd-test-1")
        self.assertTrue(share_msg.is_encrypted)
        self.assertEqual(share_msg.x, 0)
        self.assertEqual(share_msg.y, 0)
        self.assertTrue(len(share_msg.ciphertext_hex) > 0)
        self.assertTrue(len(share_msg.nonce_hex) == 24)  # 12 bytes = 24 hex chars

        # Test wire dict serialization
        wire_dict = share_msg.to_dict()
        self.assertNotIn("x", wire_dict, "Plaintext coordinate x MUST NOT be leaked on wire dict")
        self.assertNotIn("y", wire_dict, "Plaintext coordinate y MUST NOT be leaked on wire dict")
        self.assertTrue(wire_dict["is_encrypted"])
        self.assertEqual(wire_dict["nonce_hex"], share_msg.nonce_hex)
        self.assertEqual(wire_dict["ciphertext_hex"], share_msg.ciphertext_hex)

        # Test reconstruction from wire dict
        reconstructed = ShareMessage.from_dict(wire_dict)
        self.assertTrue(reconstructed.is_encrypted)
        self.assertEqual(reconstructed.ciphertext_hex, share_msg.ciphertext_hex)

    def test_broadcast_share_encryption_eavesdropper_prevention(self):
        """Verify that only nodes with mesh_key can decrypt shares, blocking passive wire eavesdroppers."""
        mesh_key = generate_mission_key()
        registry = TrustRegistry()
        gs = GroundStationNode()
        registry.set_gs_public_key(gs.public_key)

        mission_key = generate_mission_key()
        mission_key_int = int.from_bytes(mission_key, byteorder="big")
        shares = generate_shares(mission_key_int, threshold=2, num_shares=2)

        d1 = DroneNode("DRONE_1", share=shares[0], threshold=2, trust_registry=registry, mesh_key=mesh_key)
        d2 = DroneNode("DRONE_2", share=shares[1], threshold=2, trust_registry=registry, mesh_key=mesh_key)
        registry.register_drone(d1.drone_id, d1.public_key)
        registry.register_drone(d2.drone_id, d2.public_key)

        payload = {"action": "SURVEILLANCE"}
        cmd, _ = gs.create_command(payload, mission_key)
        d1.verify_gs_command(cmd)
        d2.verify_gs_command(cmd)

        app1, _ = d1.create_approval(cmd.command_id)
        app2, _ = d2.create_approval(cmd.command_id)
        d1.process_peer_approval(app2)
        d2.process_peer_approval(app1)

        # D2 publishes encrypted share
        encrypted_share = d2.provide_share(cmd.command_id)
        wire_data = encrypted_share.to_dict()

        # Eavesdropper sniffing MQTT wire sees wire_data without x, y
        self.assertNotIn("x", wire_data)
        self.assertNotIn("y", wire_data)

        # Eavesdropper node without mesh_key attempts to receive share
        eavesdropper = DroneNode("ROGUE", share=(99, 12345), threshold=2, trust_registry=registry, mesh_key=None)
        accepted = eavesdropper.receive_share(ShareMessage.from_dict(wire_data))
        self.assertFalse(accepted, "Node without mesh_key must not be able to accept/decrypt encrypted share")
        self.assertIn("no mesh_key configured", eavesdropper.last_rejection_reason)

        # Legitimate D1 with mesh_key receives and decrypts successfully
        d1_accepted = d1.receive_share(ShareMessage.from_dict(wire_data))
        self.assertTrue(d1_accepted)
        self.assertTrue(d1.can_execute(cmd.command_id))

        exec_res = d1.execute_command(cmd.command_id)
        self.assertEqual(exec_res, payload)

    def test_broadcast_share_tampering_and_wrong_key_rejection(self):
        """Verify that corrupted ciphertext or wrong mesh_key fails AEAD and is rejected."""
        valid_mesh_key = generate_mission_key()
        wrong_mesh_key = generate_mission_key()

        registry = TrustRegistry()
        d1 = DroneNode("DRONE_1", share=(1, 500), threshold=2, trust_registry=registry, mesh_key=valid_mesh_key)
        d2 = DroneNode("DRONE_2", share=(2, 600), threshold=2, trust_registry=registry, mesh_key=wrong_mesh_key)
        registry.register_drone(d1.drone_id, d1.public_key)
        registry.register_drone(d2.drone_id, d2.public_key)

        share_msg = d1.provide_share("cmd_tamper_test")

        # 1. Receiver with wrong mesh_key fails AEAD decryption
        accepted_wrong_key = d2.receive_share(share_msg)
        self.assertFalse(accepted_wrong_key)
        self.assertIn("authentication failure", d2.last_rejection_reason)

        # 2. Tampered ciphertext fails signature / AEAD
        raw_dict = share_msg.to_dict()
        # Flip hex character in ciphertext
        corrupted_ct = list(raw_dict["ciphertext_hex"])
        corrupted_ct[0] = "f" if corrupted_ct[0] != "f" else "0"
        raw_dict["ciphertext_hex"] = "".join(corrupted_ct)

        tampered_msg = ShareMessage.from_dict(raw_dict)
        # Receiver with valid key rejects tampered message
        accepted_tampered = d1.receive_share(tampered_msg)
        self.assertFalse(accepted_tampered)


if __name__ == "__main__":
    unittest.main()


