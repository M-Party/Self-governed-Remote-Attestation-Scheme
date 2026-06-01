import os
import tempfile
import unittest

from cryptography.hazmat.backends.openssl import backend as openssl_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from RPE.relying_party_enclave.ft_control import (
    FTConfig,
    FTControlManager,
    FTStateStore,
    canonical_json_bytes,
    derive_ft_quorum,
    parse_peer_addresses,
    sign_json,
    verify_json_signature,
)


class FTConfigTest(unittest.TestCase):
    def test_auto_quorum_for_even_and_odd_party_counts(self):
        self.assertEqual(derive_ft_quorum(2, 0), 1)
        self.assertEqual(derive_ft_quorum(4, 0), 2)
        self.assertEqual(derive_ft_quorum(5, 0), 3)
        self.assertEqual(derive_ft_quorum(8, 0), 4)

    def test_quorum_override_is_validated(self):
        self.assertEqual(derive_ft_quorum(4, 3), 3)
        with self.assertRaises(ValueError):
            derive_ft_quorum(4, 5)
        with self.assertRaises(ValueError):
            derive_ft_quorum(4, -1)

    def test_parse_peer_addresses(self):
        peers = parse_peer_addresses("rpe-1=127.0.0.1:56001,rpe-2=127.0.0.1:56002")
        self.assertEqual(peers["rpe-1"], "127.0.0.1:56001")
        self.assertEqual(peers["rpe-2"], "127.0.0.1:56002")

    def test_parse_peer_addresses_rejects_malformed_entries(self):
        malformed_values = [
            "=127.0.0.1:56001",
            "rpe-1=",
            "rpe-1=127.0.0.1",
            "rpe-1=:56001",
            "rpe-1=127.0.0.1:abc",
            "rpe-1=127.0.0.1:0",
            "rpe-1=127.0.0.1:65536",
            "rpe-1=127.0.0.1:56001,rpe-1=127.0.0.1:56002",
        ]
        for raw_value in malformed_values:
            with self.subTest(raw_value=raw_value):
                with self.assertRaises(ValueError):
                    parse_peer_addresses(raw_value)

    def test_config_defaults_to_disabled(self):
        config = FTConfig.from_conf({}, num_rpes=4, local_rpe_id="rpe-1")
        self.assertFalse(config.enabled)
        self.assertEqual(config.ft_quorum, 2)
        self.assertEqual(config.peer_addresses, {})

    def test_config_accepts_explicit_enabled_tokens(self):
        for token in ("1", "true", "yes", "on"):
            with self.subTest(token=token):
                config = FTConfig.from_conf({"ft": {"enabled": token}}, num_rpes=4, local_rpe_id="rpe-1")
                self.assertTrue(config.enabled)
        for token in ("0", "false", "no", "off"):
            with self.subTest(token=token):
                config = FTConfig.from_conf({"ft": {"enabled": token}}, num_rpes=4, local_rpe_id="rpe-1")
                self.assertFalse(config.enabled)

    def test_config_rejects_invalid_enabled_value(self):
        with self.assertRaises(ValueError):
            FTConfig.from_conf({"ft": {"enabled": "treu"}}, num_rpes=4, local_rpe_id="rpe-1")


class FTSigningStateTest(unittest.TestCase):
    def _key_pair(self):
        private_key = ec.generate_private_key(ec.SECP384R1(), backend=openssl_backend)
        return private_key, private_key.public_key()

    def test_canonical_json_is_order_independent(self):
        left = {"b": 2, "a": 1}
        right = {"a": 1, "b": 2}
        self.assertEqual(canonical_json_bytes(left), canonical_json_bytes(right))

    def test_sign_and_verify_json(self):
        private_key, public_key = self._key_pair()
        payload = {"target_rpe_id": "rpe-1", "tee_id": "ce-1", "attestation_counter": 1, "nonce": "n"}
        signature = sign_json(private_key, payload)
        self.assertTrue(verify_json_signature(public_key, payload, signature))
        self.assertFalse(verify_json_signature(public_key, dict(payload, nonce="changed"), signature))

    def test_counter_cache_round_trip(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "counter_cache.json")
            store = FTStateStore(path)
            self.assertEqual(store.next_local_counter("ce-1"), 1)
            self.assertEqual(store.next_local_counter("ce-1"), 2)
            reloaded = FTStateStore(path)
            self.assertEqual(reloaded.next_local_counter("ce-1"), 3)

    def test_remote_state_is_in_memory_and_newer_only(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store = FTStateStore(os.path.join(temp_dir, "counter_cache.json"))
            old_state = {"target_rpe_id": "rpe-1", "tee_id": "ce-1", "attestation_counter": 1, "nonce": "a"}
            new_state = {"target_rpe_id": "rpe-1", "tee_id": "ce-1", "attestation_counter": 2, "nonce": "b"}
            self.assertTrue(store.record_remote_state(old_state, {"sender_rpe_id": "rpe-1"}))
            self.assertFalse(store.record_remote_state(old_state, {"sender_rpe_id": "rpe-1"}))
            self.assertTrue(store.record_remote_state(new_state, {"sender_rpe_id": "rpe-1"}))
            self.assertEqual(store.get_recorded_state("rpe-1")["state"]["attestation_counter"], 2)

    def test_replay_nonce_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store = FTStateStore(os.path.join(temp_dir, "counter_cache.json"))
            self.assertTrue(store.mark_nonce_seen("nonce-1"))
            self.assertFalse(store.mark_nonce_seen("nonce-1"))


class FTControlServiceTest(unittest.TestCase):
    def _key_pair(self):
        private_key = ec.generate_private_key(ec.SECP384R1(), backend=openssl_backend)
        return private_key, private_key.public_key()

    def _pem(self, public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def test_state_update_returns_signed_echo_and_records_state(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            sender_private, sender_public = self._key_pair()
            receiver_private, receiver_public = self._key_pair()
            receiver_config = FTConfig(
                enabled=True,
                local_rpe_id="rpe-2",
                listen_host="127.0.0.1",
                listen_port=0,
                peer_addresses={},
                echo_timeout_sec=2,
                recovery_timeout_sec=2,
                expt_cache_path=os.path.join(temp_dir, "expt.json"),
                counter_cache_path=os.path.join(temp_dir, "receiver_counter.json"),
                ft_quorum=1,
            )
            receiver = FTControlManager(
                receiver_config,
                receiver_private,
                self._pem(receiver_public),
                {"rpe-1": self._pem(sender_public), "rpe-2": self._pem(receiver_public)},
            )
            receiver.start()
            try:
                sender_config = FTConfig(
                    enabled=True,
                    local_rpe_id="rpe-1",
                    listen_host="127.0.0.1",
                    listen_port=0,
                    peer_addresses={"rpe-2": receiver.bound_address()},
                    echo_timeout_sec=2,
                    recovery_timeout_sec=2,
                    expt_cache_path=os.path.join(temp_dir, "expt.json"),
                    counter_cache_path=os.path.join(temp_dir, "sender_counter.json"),
                    ft_quorum=1,
                )
                sender = FTControlManager(
                    sender_config,
                    sender_private,
                    self._pem(sender_public),
                    {"rpe-1": self._pem(sender_public), "rpe-2": self._pem(receiver_public)},
                )
                ok, echoes = sender.propagate_attestation_state("ce-1")
                self.assertTrue(ok)
                self.assertEqual(len(echoes), 1)
                self.assertEqual(echoes[0]["responder_rpe_id"], "rpe-2")
                self.assertEqual(
                    receiver.state_store.get_recorded_state("rpe-1")["state"]["tee_id"], "ce-1"
                )
            finally:
                receiver.stop()


if __name__ == "__main__":
    unittest.main()
