import os
import configparser
import tempfile
import threading
import time
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
    local_echo_counts_toward_quorum,
    parse_peer_addresses,
    sign_json,
    verify_json_signature,
)


class FTConfigTest(unittest.TestCase):
    def test_auto_quorum_for_even_and_odd_party_counts(self):
        self.assertEqual(derive_ft_quorum(2, 0), 1)
        self.assertEqual(derive_ft_quorum(3, 0), 2)
        self.assertEqual(derive_ft_quorum(4, 0), 3)
        self.assertEqual(derive_ft_quorum(5, 0), 3)
        self.assertEqual(derive_ft_quorum(6, 0), 4)
        self.assertEqual(derive_ft_quorum(7, 0), 4)
        self.assertEqual(derive_ft_quorum(8, 0), 5)

    def test_local_echo_quorum_policy_by_party_count(self):
        self.assertFalse(local_echo_counts_toward_quorum(2))
        self.assertTrue(local_echo_counts_toward_quorum(3))
        self.assertTrue(local_echo_counts_toward_quorum(5))

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
        self.assertEqual(config.ft_quorum, 3)
        self.assertEqual(config.num_rpes, 4)
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
                    ft_quorum=2,
                )
                sender = FTControlManager(
                    sender_config,
                    sender_private,
                    self._pem(sender_public),
                    {"rpe-1": self._pem(sender_public), "rpe-2": self._pem(receiver_public)},
                )
                ok, echoes = sender.propagate_attestation_state("ce-1")
                self.assertTrue(ok)
                self.assertEqual(len(echoes), 2)
                responders = {echo["responder_rpe_id"] for echo in echoes}
                self.assertEqual(responders, {"rpe-1", "rpe-2"})
                self.assertEqual(
                    receiver.state_store.get_recorded_state("rpe-1")["state"]["tee_id"], "ce-1"
                )
            finally:
                receiver.stop()

    def test_state_update_uses_grpc_transport(self):
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
                response = sender.grpc_post_json(
                    receiver.bound_address(),
                    "StateUpdate",
                    {
                        "sender_rpe_id": "rpe-1",
                        "state": {
                            "target_rpe_id": "rpe-1",
                            "tee_id": "ce-1",
                            "attestation_counter": 1,
                            "nonce": "grpc-nonce",
                        },
                    },
                    2,
                )
                self.assertEqual(response["status"], 0)
                self.assertEqual(response["echo"]["responder_rpe_id"], "rpe-2")
                self.assertIn("timings", response)
                self.assertGreaterEqual(response["timings"]["total_ms"], 0)
                self.assertGreaterEqual(response["timings"]["record_state_ms"], 0)
                self.assertGreaterEqual(response["timings"]["sign_echo_ms"], 0)
            finally:
                receiver.stop()

    def test_single_rpe_state_propagation_succeeds_without_peer_echo(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            private_key, public_key = self._key_pair()
            config = FTConfig(
                enabled=True,
                local_rpe_id="rpe-1",
                listen_host="127.0.0.1",
                listen_port=0,
                peer_addresses={},
                echo_timeout_sec=2,
                recovery_timeout_sec=2,
                expt_cache_path=os.path.join(temp_dir, "expt.json"),
                counter_cache_path=os.path.join(temp_dir, "counter.json"),
                ft_quorum=1,
            )
            manager = FTControlManager(
                config,
                private_key,
                self._pem(public_key),
                {"rpe-1": self._pem(public_key)},
            )
            ok, echoes = manager.propagate_attestation_state("ce-1")
            self.assertTrue(ok)
            self.assertEqual(len(echoes), 1)
            self.assertEqual(echoes[0]["responder_rpe_id"], "rpe-1")
            self.assertEqual(manager.state_store.next_local_counter("ce-1"), 2)

    def test_propagation_counts_local_echo_toward_quorum(self):
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
                ft_quorum=2,
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
                    peer_addresses={
                        "rpe-2": receiver.bound_address(),
                        "rpe-3": "127.0.0.1:1",
                    },
                    echo_timeout_sec=2,
                    recovery_timeout_sec=2,
                    expt_cache_path=os.path.join(temp_dir, "expt.json"),
                    counter_cache_path=os.path.join(temp_dir, "sender_counter.json"),
                    ft_quorum=2,
                )
                sender = FTControlManager(
                    sender_config,
                    sender_private,
                    self._pem(sender_public),
                    {"rpe-1": self._pem(sender_public), "rpe-2": self._pem(receiver_public)},
                )
                ok, echoes = sender.propagate_attestation_state("ce-1")
                self.assertTrue(ok)
                responders = {echo["responder_rpe_id"] for echo in echoes}
                self.assertEqual(responders, {"rpe-1", "rpe-2"})
                timings = sender.last_propagation_timings
                self.assertEqual(timings["tee_id"], "ce-1")
                self.assertGreaterEqual(timings["total_ms"], 0)
                self.assertGreaterEqual(timings["local_sign_echo_ms"], 0)
                self.assertIn("rpe-2", timings["peers"])
                self.assertGreaterEqual(timings["peers"]["rpe-2"]["rpc_total_ms"], 0)
                self.assertGreaterEqual(timings["peers"]["rpe-2"]["local_verify_echo_ms"], 0)
                self.assertIn("remote_timings", timings["peers"]["rpe-2"])
            finally:
                receiver.stop()

    def test_n2_propagation_waits_for_peer_echo(self):
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
                num_rpes=2,
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
                    num_rpes=2,
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
                timings = sender.last_propagation_timings
                self.assertEqual(timings["quorum_target"], 1)
                self.assertIn("rpe-2", timings["peers"])
                self.assertTrue(timings["peers"]["rpe-2"]["accepted"])
                self.assertGreaterEqual(timings["peers"]["rpe-2"]["rpc_total_ms"], 0)
                self.assertGreaterEqual(timings["peers"]["rpe-2"]["local_verify_echo_ms"], 0)
            finally:
                receiver.stop()

    def test_late_peer_response_after_quorum_does_not_verify_echo(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            sender_private, sender_public = self._key_pair()
            fast_private, fast_public = self._key_pair()
            slow_private, slow_public = self._key_pair()
            config = FTConfig(
                enabled=True,
                local_rpe_id="rpe-1",
                listen_host="127.0.0.1",
                listen_port=0,
                peer_addresses={"rpe-2": "fast-peer", "rpe-3": "slow-peer"},
                echo_timeout_sec=1,
                recovery_timeout_sec=1,
                expt_cache_path=os.path.join(temp_dir, "expt.json"),
                counter_cache_path=os.path.join(temp_dir, "counter.json"),
                ft_quorum=2,
            )
            sender = FTControlManager(
                config,
                sender_private,
                self._pem(sender_public),
                {
                    "rpe-1": self._pem(sender_public),
                    "rpe-2": self._pem(fast_public),
                    "rpe-3": self._pem(slow_public),
                },
            )

            def make_echo(responder_rpe_id, private_key, state):
                echo = {
                    "responder_rpe_id": responder_rpe_id,
                    "target_rpe_id": state["target_rpe_id"],
                    "tee_id": state["tee_id"],
                    "attestation_counter": state["attestation_counter"],
                    "nonce": state["nonce"],
                }
                echo["signature"] = sign_json(private_key, echo)
                return echo

            def fake_post_json(address, _method, payload, _timeout, cancel_event=None):
                if address == "slow-peer":
                    time.sleep(0.2)
                    return {
                        "status": 0,
                        "echo": make_echo("rpe-3", slow_private, payload["state"]),
                        "timings": {},
                    }
                return {
                    "status": 0,
                    "echo": make_echo("rpe-2", fast_private, payload["state"]),
                    "timings": {},
                }

            verified_responders = []
            original_validate = sender._validate_echo_with_reason

            def recording_validate(echo, expected_state):
                verified_responders.append(echo.get("responder_rpe_id"))
                return original_validate(echo, expected_state)

            sender.grpc_post_json = fake_post_json
            sender._validate_echo_with_reason = recording_validate

            ok, echoes = sender.propagate_attestation_state("ce-1")
            time.sleep(0.3)

            self.assertTrue(ok)
            self.assertEqual({echo["responder_rpe_id"] for echo in echoes}, {"rpe-1", "rpe-2"})
            self.assertEqual(verified_responders, ["rpe-2"])

    def test_invalid_state_update_does_not_consume_nonce(self):
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
            state = {
                "target_rpe_id": "rpe-1",
                "tee_id": "ce-1",
                "attestation_counter": 1,
                "nonce": "same-nonce",
            }
            bad_update = {
                "sender_rpe_id": "rpe-1",
                "state": {
                    "target_rpe_id": "rpe-1",
                    "tee_id": "ce-1",
                    "attestation_counter": 1,
                },
            }
            self.assertEqual(receiver.handle_state_update(bad_update)["status"], 1)

            good_update = {
                "sender_rpe_id": "rpe-1",
                "state": dict(state),
            }
            response = receiver.handle_state_update(good_update)
            self.assertEqual(response["status"], 0)


class FTGeneratedConfigTest(unittest.TestCase):
    def test_generated_ft_peer_addresses_are_per_party(self):
        from performance.setup_multi_party import MultiPartySetup

        with tempfile.TemporaryDirectory(prefix="sras_ft_setup_") as root:
            for name in ("fabric_service/fabric_client/config", "RPO", "RPE"):
                os.makedirs(os.path.join(root, name), exist_ok=True)
            with open(os.path.join(root, "fabric_service/fabric_client/config/config.toml"), "w") as f:
                f.write("[grpc]\nport = \"50051\"\n")
            with open(os.path.join(root, "RPO/config.toml"), "w") as f:
                f.write("[rpo]\nrpe_id = \"rpe-1\"\nport = \"4433\"\npolicies_path = \"policies.json\"\n")
            with open(os.path.join(root, "RPO/policies.json.template"), "w") as f:
                f.write(
                    '{"session_id":"s","rpe":[],"rpe_info":{},"tcb":[],"job":[],"ce":[],"connection":[]}'
                )
            with open(os.path.join(root, "RPE/config.toml"), "w") as f:
                f.write(
                    "[rpe]\n"
                    "rpe_id = \"rpe-1\"\n"
                    "rpe_port = \"4455\"\n"
                    "rpo_address = \"127.0.0.1\"\n"
                    "rpo_port = \"4433\"\n"
                    "grpc_server_address = \"127.0.0.1:50051\"\n"
                )
            setup = MultiPartySetup(base_dir=root, num_parties=3, ft_enabled=True, ft_base_port=56001)
            setup.setup_multiple_parties()
            cfg = configparser.ConfigParser()
            cfg.read(os.path.join(root, "RPE_party1/config.toml"))
            self.assertEqual(cfg["ft"]["enabled"], "true")
            self.assertEqual(cfg["ft"]["listen_port"].strip('"'), "56001")
            self.assertIn("rpe-2=127.0.0.1:56002", cfg["ft"]["peer_addresses"])
            self.assertIn("rpe-3=127.0.0.1:56003", cfg["ft"]["peer_addresses"])

            for party_id in (1, 2, 3):
                rpo_cfg = configparser.ConfigParser()
                rpo_cfg.read(os.path.join(root, "RPO_party%d/config.toml" % party_id))
                self.assertEqual(rpo_cfg["rpo"]["rpe_id"].strip('"'), "rpe-%d" % party_id)
                self.assertEqual(rpo_cfg["rpo"]["policies_path"].strip('"'), "policies-3.json")


class FTRecoveryTest(unittest.TestCase):
    def _key_pair(self):
        private_key = ec.generate_private_key(ec.SECP384R1(), backend=openssl_backend)
        return private_key, private_key.public_key()

    def _pem(self, public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def test_evidence_update_updates_key_only_after_quote_verifier_accepts(self):
        _old_private, old_public = self._key_pair()
        _new_private, new_public = self._key_pair()
        local_private, local_public = self._key_pair()
        calls = []

        def verifier(evidence_quote, signing_key_pem, encryption_key_pem, expt_hash, nonce):
            calls.append((evidence_quote, signing_key_pem, encryption_key_pem, expt_hash, nonce))
            return evidence_quote == "fresh-quote" and signing_key_pem == self._pem(new_public)

        updated_keys = []

        with tempfile.TemporaryDirectory() as temp_dir:
            config = FTConfig(
                enabled=True,
                local_rpe_id="rpe-2",
                listen_host="127.0.0.1",
                listen_port=0,
                peer_addresses={},
                echo_timeout_sec=2,
                recovery_timeout_sec=2,
                expt_cache_path=os.path.join(temp_dir, "expt.json"),
                counter_cache_path=os.path.join(temp_dir, "counter.json"),
                ft_quorum=1,
            )
            manager = FTControlManager(
                config,
                local_private,
                self._pem(local_public),
                {"rpe-1": self._pem(old_public), "rpe-2": self._pem(local_public)},
                quote_verifier=verifier,
                on_peer_key_update=lambda rpe_id, signing_key, encryption_key: updated_keys.append(
                    (rpe_id, signing_key, encryption_key)
                ),
            )
            response = manager.handle_evidence_update({
                "recovering_rpe_id": "rpe-1",
                "evidence_quote": "fresh-quote",
                "rpe_public_signing_key": self._pem(new_public),
                "rpe_public_encryption_key": "new-encryption-key",
                "expt_hash": "hash-a",
                "nonce": "recovery-nonce",
            })
            self.assertEqual(response["status"], 0)
            self.assertEqual(manager.peer_public_keys["rpe-1"], self._pem(old_public))
            self.assertEqual(calls, [])
            self.assertEqual(updated_keys, [])
            processed = manager.process_pending_evidence_updates()
            self.assertEqual(processed["accepted"], ["rpe-1"])
            self.assertEqual(processed["rejected"], [])
            self.assertEqual(manager.peer_public_keys["rpe-1"], self._pem(new_public))
            self.assertEqual(len(calls), 1)
            self.assertEqual(updated_keys, [("rpe-1", self._pem(new_public), "new-encryption-key")])

    def test_evidence_update_rejects_failed_quote_verification(self):
        local_private, local_public = self._key_pair()
        _peer_private, peer_public = self._key_pair()
        with tempfile.TemporaryDirectory() as temp_dir:
            config = FTConfig(
                enabled=True,
                local_rpe_id="rpe-2",
                listen_host="127.0.0.1",
                listen_port=0,
                peer_addresses={},
                echo_timeout_sec=2,
                recovery_timeout_sec=2,
                expt_cache_path=os.path.join(temp_dir, "expt.json"),
                counter_cache_path=os.path.join(temp_dir, "counter.json"),
                ft_quorum=1,
            )
            manager = FTControlManager(
                config,
                local_private,
                self._pem(local_public),
                {"rpe-1": self._pem(peer_public), "rpe-2": self._pem(local_public)},
                quote_verifier=lambda evidence_quote, signing_key_pem, encryption_key_pem, expt_hash, nonce: False,
            )
            response = manager.handle_evidence_update({
                "recovering_rpe_id": "rpe-1",
                "evidence_quote": "bad-quote",
                "rpe_public_signing_key": self._pem(peer_public),
                "rpe_public_encryption_key": "encryption-key",
                "expt_hash": "hash-a",
                "nonce": "recovery-nonce",
            })
            self.assertEqual(response["status"], 0)
            processed = manager.process_pending_evidence_updates()
            self.assertEqual(processed["accepted"], [])
            self.assertEqual(processed["rejected"], ["rpe-1"])
            self.assertEqual(manager.peer_public_keys["rpe-1"], self._pem(peer_public))

    def test_evidence_update_returns_before_slow_quote_verification(self):
        _old_private, old_public = self._key_pair()
        _new_private, new_public = self._key_pair()
        local_private, local_public = self._key_pair()
        verifier_started = threading.Event()
        verifier_release = threading.Event()
        updated_keys = []
        verifier_threads = []

        def verifier(_evidence_quote, _signing_key_pem, _encryption_key_pem, _expt_hash, _nonce):
            verifier_threads.append(threading.current_thread().name)
            verifier_started.set()
            verifier_release.wait(timeout=1)
            return True

        with tempfile.TemporaryDirectory() as temp_dir:
            config = FTConfig(
                enabled=True,
                local_rpe_id="rpe-2",
                listen_host="127.0.0.1",
                listen_port=0,
                peer_addresses={},
                echo_timeout_sec=2,
                recovery_timeout_sec=2,
                expt_cache_path=os.path.join(temp_dir, "expt.json"),
                counter_cache_path=os.path.join(temp_dir, "counter.json"),
                ft_quorum=1,
            )
            manager = FTControlManager(
                config,
                local_private,
                self._pem(local_public),
                {"rpe-1": self._pem(old_public), "rpe-2": self._pem(local_public)},
                quote_verifier=verifier,
                on_peer_key_update=lambda rpe_id, signing_key, encryption_key: updated_keys.append(
                    (rpe_id, signing_key, encryption_key)
                ),
            )
            started_at = time.time()
            response = manager.handle_evidence_update({
                "recovering_rpe_id": "rpe-1",
                "evidence_quote": "fresh-quote",
                "rpe_public_signing_key": self._pem(new_public),
                "rpe_public_encryption_key": "new-encryption-key",
                "expt_hash": "hash-a",
                "nonce": "recovery-nonce",
            })
            elapsed = time.time() - started_at
            self.assertEqual(response["status"], 0)
            self.assertLess(elapsed, 0.1)
            self.assertEqual(manager.peer_public_keys["rpe-1"], self._pem(old_public))
            self.assertFalse(verifier_started.wait(timeout=0.05))
            processed = manager.process_pending_evidence_updates()
            self.assertEqual(processed["accepted"], ["rpe-1"])
            self.assertTrue(verifier_started.is_set())
            verifier_release.set()
            self.assertEqual(manager.peer_public_keys["rpe-1"], self._pem(new_public))
            self.assertEqual(updated_keys, [("rpe-1", self._pem(new_public), "new-encryption-key")])
            self.assertEqual(verifier_threads, [threading.current_thread().name])

    def test_evidence_updates_keep_latest_pending_quote_per_rpe(self):
        _old_private, old_public = self._key_pair()
        first_private, first_public = self._key_pair()
        second_private, second_public = self._key_pair()
        local_private, local_public = self._key_pair()
        del first_private, second_private
        verifier_calls = []
        updated_keys = []

        def verifier(_evidence_quote, signing_key_pem, _encryption_key_pem, _expt_hash, _nonce):
            verifier_calls.append((threading.current_thread().name, signing_key_pem))
            time.sleep(0.02)
            return True

        with tempfile.TemporaryDirectory() as temp_dir:
            config = FTConfig(
                enabled=True,
                local_rpe_id="rpe-2",
                listen_host="127.0.0.1",
                listen_port=0,
                peer_addresses={},
                echo_timeout_sec=2,
                recovery_timeout_sec=2,
                expt_cache_path=os.path.join(temp_dir, "expt.json"),
                counter_cache_path=os.path.join(temp_dir, "counter.json"),
                ft_quorum=1,
            )
            manager = FTControlManager(
                config,
                local_private,
                self._pem(local_public),
                {"rpe-1": self._pem(old_public), "rpe-2": self._pem(local_public)},
                quote_verifier=verifier,
                on_peer_key_update=lambda rpe_id, signing_key, encryption_key: updated_keys.append(
                    (rpe_id, signing_key, encryption_key)
                ),
            )
            for public_key, encryption_key in (
                (first_public, "first-encryption-key"),
                (second_public, "second-encryption-key"),
            ):
                response = manager.handle_evidence_update({
                    "recovering_rpe_id": "rpe-1",
                    "evidence_quote": "fresh-quote",
                    "rpe_public_signing_key": self._pem(public_key),
                    "rpe_public_encryption_key": encryption_key,
                    "expt_hash": "hash-a",
                    "nonce": "recovery-nonce",
                })
                self.assertEqual(response["status"], 0)

            self.assertEqual(verifier_calls, [])
            processed = manager.process_pending_evidence_updates()
            self.assertEqual(processed["accepted"], ["rpe-1"])
            self.assertEqual(len(verifier_calls), 1)
            self.assertEqual(verifier_calls[0][1], self._pem(second_public))
            self.assertEqual(updated_keys, [("rpe-1", self._pem(second_public), "second-encryption-key")])

    def test_recovery_query_returns_cached_phase2_evidence_quote_and_signed_state(self):
        class FakeQuoteProvider:
            def get_cached_phase2_evidence_for_recovery(self):
                return {
                    "evidence_quote": "phase2-quote",
                    "rpe_public_signing_key": "signing-key",
                    "rpe_public_encryption_key": "encryption-key",
                    "expt_hash": "hash-a",
                }

        with tempfile.TemporaryDirectory() as temp_dir:
            recovering_private, recovering_public = self._key_pair()
            responder_private, responder_public = self._key_pair()
            config = FTConfig(
                enabled=True,
                local_rpe_id="rpe-2",
                listen_host="127.0.0.1",
                listen_port=0,
                peer_addresses={},
                echo_timeout_sec=2,
                recovery_timeout_sec=2,
                expt_cache_path=os.path.join(temp_dir, "expt.json"),
                counter_cache_path=os.path.join(temp_dir, "counter.json"),
                ft_quorum=1,
            )
            manager = FTControlManager(
                config,
                responder_private,
                self._pem(responder_public),
                {"rpe-1": self._pem(recovering_public), "rpe-2": self._pem(responder_public)},
                quote_verifier=FakeQuoteProvider(),
            )
            state = {
                "target_rpe_id": "rpe-1",
                "tee_id": "ce-1",
                "attestation_counter": 7,
                "nonce": "state-nonce",
            }
            update = {
                "sender_rpe_id": "rpe-1",
                "state": state,
                "signature": sign_json(recovering_private, state),
            }
            self.assertEqual(manager.handle_state_update(update)["status"], 0)

            response = manager.handle_recovery_query({
                "recovering_rpe_id": "rpe-1",
                "recovery_nonce": "recovery-nonce",
            })
            self.assertEqual(response["status"], 0)
            self.assertEqual(response["evidence_quote"], "phase2-quote")
            self.assertEqual(response["rpe_public_signing_key"], "signing-key")
            self.assertEqual(response["rpe_public_encryption_key"], "encryption-key")
            self.assertEqual(
                response["signed_state"]["state"]["recorded_attestation_state"], state
            )
            self.assertEqual(response["signed_state"]["state"]["recovery_nonce"], "recovery-nonce")

    def test_recovery_query_without_recorded_state_returns_zero_counter(self):
        class FakeQuoteProvider:
            def get_cached_phase2_evidence_for_recovery(self):
                return {
                    "evidence_quote": "phase2-quote",
                    "rpe_public_signing_key": "signing-key",
                    "rpe_public_encryption_key": "encryption-key",
                    "expt_hash": "hash-a",
                }

        with tempfile.TemporaryDirectory() as temp_dir:
            recovering_private, recovering_public = self._key_pair()
            responder_private, responder_public = self._key_pair()
            config = FTConfig(
                enabled=True,
                local_rpe_id="rpe-4",
                listen_host="127.0.0.1",
                listen_port=0,
                peer_addresses={},
                echo_timeout_sec=2,
                recovery_timeout_sec=2,
                expt_cache_path=os.path.join(temp_dir, "expt.json"),
                counter_cache_path=os.path.join(temp_dir, "counter.json"),
                ft_quorum=1,
            )
            manager = FTControlManager(
                config,
                responder_private,
                self._pem(responder_public),
                {"rpe-1": self._pem(recovering_public), "rpe-4": self._pem(responder_public)},
                quote_verifier=FakeQuoteProvider(),
            )
            response = manager.handle_recovery_query({
                "recovering_rpe_id": "rpe-1",
                "recovery_nonce": "recovery-nonce",
            })
            self.assertEqual(response["status"], 0)
            zero_state = response["signed_state"]["state"]["recorded_attestation_state"]
            self.assertEqual(zero_state["target_rpe_id"], "rpe-1")
            self.assertEqual(zero_state["attestation_counter"], 0)
            self.assertEqual(zero_state["tee_id"], "")

    def test_recover_local_counter_from_latest_valid_grpc_response(self):
        class FakeQuoteProvider:
            def __init__(self):
                self.verified = []

            def verify_phase2_evidence_quote(self, evidence_quote, signing_key_pem, encryption_key_pem, expt_hash, rpe_id=None):
                self.verified.append((evidence_quote, signing_key_pem, encryption_key_pem, expt_hash, rpe_id))
                return evidence_quote == "phase2-quote"

        with tempfile.TemporaryDirectory() as temp_dir:
            recovering_private, recovering_public = self._key_pair()
            _old_peer_private, old_peer_public = self._key_pair()
            peer_private, peer_public = self._key_pair()
            peer_config = FTConfig(
                enabled=True,
                local_rpe_id="rpe-2",
                listen_host="127.0.0.1",
                listen_port=0,
                peer_addresses={},
                echo_timeout_sec=2,
                recovery_timeout_sec=2,
                expt_cache_path=os.path.join(temp_dir, "peer_expt.json"),
                counter_cache_path=os.path.join(temp_dir, "peer_counter.json"),
                ft_quorum=1,
            )

            peer_public_pem = self._pem(peer_public)

            class PeerQuoteProvider:
                def get_cached_phase2_evidence_for_recovery(self):
                    return {
                        "evidence_quote": "phase2-quote",
                        "rpe_public_signing_key": peer_public_pem,
                        "rpe_public_encryption_key": "peer-encryption-key",
                        "expt_hash": "hash-a",
                    }

            peer = FTControlManager(
                peer_config,
                peer_private,
                peer_public_pem,
                {"rpe-1": self._pem(recovering_public), "rpe-2": peer_public_pem},
                quote_verifier=PeerQuoteProvider(),
            )
            state = {
                "target_rpe_id": "rpe-1",
                "tee_id": "ce-1",
                "attestation_counter": 9,
                "nonce": "state-nonce",
            }
            self.assertEqual(peer.handle_state_update({
                "sender_rpe_id": "rpe-1",
                "state": state,
            })["status"], 0)
            peer.start()
            try:
                recovering_config = FTConfig(
                    enabled=True,
                    local_rpe_id="rpe-1",
                    listen_host="127.0.0.1",
                    listen_port=0,
                    peer_addresses={"rpe-2": peer.bound_address()},
                    echo_timeout_sec=2,
                    recovery_timeout_sec=2,
                    expt_cache_path=os.path.join(temp_dir, "recovering_expt.json"),
                    counter_cache_path=os.path.join(temp_dir, "recovering_counter.json"),
                    ft_quorum=1,
                )
                quote_provider = FakeQuoteProvider()
                recovering = FTControlManager(
                    recovering_config,
                    recovering_private,
                    self._pem(recovering_public),
                    {"rpe-1": self._pem(recovering_public), "rpe-2": self._pem(old_peer_public)},
                    quote_verifier=quote_provider,
                    nonce_factory=lambda: "fixed-nonce",
                )
                ok, selected, responses = recovering.recover_latest_attestation_state()
                self.assertTrue(ok)
                self.assertEqual(selected["state"]["attestation_counter"], 9)
                self.assertEqual(recovering.state_store.next_local_counter("ce-1"), 10)
                self.assertEqual(recovering.peer_public_keys["rpe-2"], peer_public_pem)
                self.assertEqual(len(responses), 1)
                self.assertEqual(len(quote_provider.verified), 1)
            finally:
                peer.stop()

    def test_recovery_validates_responses_after_query_threads_join(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            private_key, public_key = self._key_pair()
            config = FTConfig(
                enabled=True,
                local_rpe_id="rpe-1",
                listen_host="127.0.0.1",
                listen_port=0,
                peer_addresses={"rpe-2": "unused"},
                echo_timeout_sec=2,
                recovery_timeout_sec=2,
                expt_cache_path=os.path.join(temp_dir, "expt.json"),
                counter_cache_path=os.path.join(temp_dir, "counter.json"),
                ft_quorum=1,
            )
            manager = FTControlManager(
                config,
                private_key,
                self._pem(public_key),
                {"rpe-1": self._pem(public_key)},
                nonce_factory=lambda: "fixed-nonce",
            )
            caller_thread = threading.current_thread()
            validation_threads = []

            def fake_post_json(_address, _method, _payload, _timeout, cancel_event=None):
                return {"status": 0, "recovery_nonce": "fixed-nonce", "responder_rpe_id": "rpe-2"}

            def fake_validate(_response, _expected_nonce):
                validation_threads.append(threading.current_thread())
                return {
                    "responder_rpe_id": "rpe-2",
                    "state": {
                        "target_rpe_id": "rpe-1",
                        "tee_id": "ce-1",
                        "attestation_counter": 4,
                    },
                    "signed_state": {},
                    "rpe_public_signing_key": self._pem(public_key),
                    "rpe_public_encryption_key": "enc",
                    "expt_hash": "hash",
                    "timings": {
                        "evidence_quote_verification_ms": 1.0,
                        "signed_state_verification_ms": 1.0,
                    },
                }

            manager.grpc_post_json = fake_post_json
            manager._validate_recovery_response = fake_validate

            ok, selected, responses = manager.recover_latest_attestation_state()

            self.assertTrue(ok)
            self.assertEqual(selected["state"]["attestation_counter"], 4)
            self.assertEqual(len(responses), 1)
            self.assertEqual(validation_threads, [caller_thread])

    def test_warmup_peer_channels_uses_ping_rpc(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            peer_private, peer_public = self._key_pair()
            recovering_private, recovering_public = self._key_pair()
            peer_config = FTConfig(
                enabled=True,
                local_rpe_id="rpe-2",
                listen_host="127.0.0.1",
                listen_port=0,
                peer_addresses={},
                echo_timeout_sec=2,
                recovery_timeout_sec=2,
                expt_cache_path=os.path.join(temp_dir, "peer_expt.json"),
                counter_cache_path=os.path.join(temp_dir, "peer_counter.json"),
                ft_quorum=1,
            )
            peer = FTControlManager(
                peer_config,
                peer_private,
                self._pem(peer_public),
                {"rpe-1": self._pem(recovering_public), "rpe-2": self._pem(peer_public)},
            )
            peer.start()
            try:
                recovering_config = FTConfig(
                    enabled=True,
                    local_rpe_id="rpe-1",
                    listen_host="127.0.0.1",
                    listen_port=0,
                    peer_addresses={"rpe-2": peer.bound_address()},
                    echo_timeout_sec=2,
                    recovery_timeout_sec=2,
                    expt_cache_path=os.path.join(temp_dir, "recovering_expt.json"),
                    counter_cache_path=os.path.join(temp_dir, "recovering_counter.json"),
                    ft_quorum=1,
                )
                recovering = FTControlManager(
                    recovering_config,
                    recovering_private,
                    self._pem(recovering_public),
                    {"rpe-1": self._pem(recovering_public), "rpe-2": self._pem(peer_public)},
                    nonce_factory=lambda: "warmup-nonce",
                )
                result = recovering.warmup_peer_channels(timeout=1.0)
                self.assertEqual(result["warmed"], 1)
                self.assertEqual(result["total"], 1)
                self.assertTrue(result["peers"]["rpe-2"]["ok"])
            finally:
                peer.stop()

    def test_broadcast_evidence_update_can_wait_for_peer_response(self):
        _old_private, old_public = self._key_pair()
        _new_private, new_public = self._key_pair()
        recovering_private, recovering_public = self._key_pair()
        peer_private, peer_public = self._key_pair()
        updated_keys = []

        def verifier(evidence_quote, signing_key_pem, encryption_key_pem, expt_hash, nonce):
            return (
                evidence_quote == "fresh-quote"
                and signing_key_pem == self._pem(new_public)
                and encryption_key_pem == "new-encryption-key"
                and expt_hash == "hash-a"
                and nonce == "fresh-nonce"
            )

        with tempfile.TemporaryDirectory() as temp_dir:
            peer_config = FTConfig(
                enabled=True,
                local_rpe_id="rpe-2",
                listen_host="127.0.0.1",
                listen_port=0,
                peer_addresses={},
                echo_timeout_sec=2,
                recovery_timeout_sec=2,
                expt_cache_path=os.path.join(temp_dir, "peer_expt.json"),
                counter_cache_path=os.path.join(temp_dir, "peer_counter.json"),
                ft_quorum=1,
            )
            peer = FTControlManager(
                peer_config,
                peer_private,
                self._pem(peer_public),
                {"rpe-1": self._pem(old_public), "rpe-2": self._pem(peer_public)},
                quote_verifier=verifier,
                on_peer_key_update=lambda rpe_id, signing_key, encryption_key: updated_keys.append(
                    (rpe_id, signing_key, encryption_key)
                ),
            )
            peer.start()
            try:
                recovering_config = FTConfig(
                    enabled=True,
                    local_rpe_id="rpe-1",
                    listen_host="127.0.0.1",
                    listen_port=0,
                    peer_addresses={"rpe-2": peer.bound_address()},
                    echo_timeout_sec=2,
                    recovery_timeout_sec=2,
                    expt_cache_path=os.path.join(temp_dir, "recovering_expt.json"),
                    counter_cache_path=os.path.join(temp_dir, "recovering_counter.json"),
                    ft_quorum=1,
                )
                recovering = FTControlManager(
                    recovering_config,
                    recovering_private,
                    self._pem(recovering_public),
                    {"rpe-1": self._pem(recovering_public), "rpe-2": self._pem(peer_public)},
                    nonce_factory=lambda: "fresh-nonce",
                )
                started_at = time.time()
                ok, peers = recovering.broadcast_evidence_update({
                    "evidence_quote": "fresh-quote",
                    "rpe_public_signing_key": self._pem(new_public),
                    "rpe_public_encryption_key": "new-encryption-key",
                    "expt_hash": "hash-a",
                }, wait_for_response=True)
                elapsed = time.time() - started_at
                self.assertTrue(ok)
                self.assertEqual(peers, ["rpe-2"])
                self.assertLess(elapsed, 2.0)
            finally:
                peer.stop()

    def test_broadcast_evidence_update_dispatch_does_not_wait_for_peer(self):
        recovering_private, recovering_public = self._key_pair()
        with tempfile.TemporaryDirectory() as temp_dir:
            recovering_config = FTConfig(
                enabled=True,
                local_rpe_id="rpe-1",
                listen_host="127.0.0.1",
                listen_port=0,
                peer_addresses={"rpe-2": "127.0.0.1:1"},
                echo_timeout_sec=2,
                recovery_timeout_sec=2,
                expt_cache_path=os.path.join(temp_dir, "recovering_expt.json"),
                counter_cache_path=os.path.join(temp_dir, "recovering_counter.json"),
                ft_quorum=1,
            )
            recovering = FTControlManager(
                recovering_config,
                recovering_private,
                self._pem(recovering_public),
                {"rpe-1": self._pem(recovering_public)},
                nonce_factory=lambda: "fresh-nonce",
            )
            started_at = time.time()
            ok, peers = recovering.broadcast_evidence_update({
                "evidence_quote": "fresh-quote",
                "rpe_public_signing_key": self._pem(recovering_public),
                "rpe_public_encryption_key": "new-encryption-key",
                "expt_hash": "hash-a",
            })
            elapsed = time.time() - started_at
            self.assertTrue(ok)
            self.assertEqual(peers, ["rpe-2"])
            self.assertLess(elapsed, 1.0)

    def test_broadcast_evidence_update_wait_mode_fails_when_peer_unavailable(self):
        recovering_private, recovering_public = self._key_pair()
        with tempfile.TemporaryDirectory() as temp_dir:
            recovering_config = FTConfig(
                enabled=True,
                local_rpe_id="rpe-1",
                listen_host="127.0.0.1",
                listen_port=0,
                peer_addresses={"rpe-2": "127.0.0.1:1"},
                echo_timeout_sec=2,
                recovery_timeout_sec=2,
                expt_cache_path=os.path.join(temp_dir, "recovering_expt.json"),
                counter_cache_path=os.path.join(temp_dir, "recovering_counter.json"),
                ft_quorum=1,
            )
            recovering = FTControlManager(
                recovering_config,
                recovering_private,
                self._pem(recovering_public),
                {"rpe-1": self._pem(recovering_public)},
                nonce_factory=lambda: "fresh-nonce",
            )
            started_at = time.time()
            ok, peers = recovering.broadcast_evidence_update({
                "evidence_quote": "fresh-quote",
                "rpe_public_signing_key": self._pem(recovering_public),
                "rpe_public_encryption_key": "new-encryption-key",
                "expt_hash": "hash-a",
            }, wait_for_response=True)
            elapsed = time.time() - started_at
            self.assertFalse(ok)
            self.assertEqual(peers, [])
            self.assertLess(elapsed, 2.0)

    def test_recovery_requires_online_peer_even_for_single_rpe_config(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            private_key, public_key = self._key_pair()
            config = FTConfig(
                enabled=True,
                local_rpe_id="rpe-1",
                listen_host="127.0.0.1",
                listen_port=0,
                peer_addresses={},
                echo_timeout_sec=2,
                recovery_timeout_sec=2,
                expt_cache_path=os.path.join(temp_dir, "expt.json"),
                counter_cache_path=os.path.join(temp_dir, "counter.json"),
                ft_quorum=1,
            )
            manager = FTControlManager(
                config,
                private_key,
                self._pem(public_key),
                {"rpe-1": self._pem(public_key)},
            )
            ok, selected, responses = manager.recover_latest_attestation_state()
            self.assertFalse(ok)
            self.assertIsNone(selected)
            self.assertEqual(responses, [])


    def test_grpc_channel_pool_reuses_channel_for_same_address(self):
        from unittest.mock import MagicMock, patch

        with tempfile.TemporaryDirectory() as temp_dir:
            private_key, public_key = self._key_pair()
            config = FTConfig(
                enabled=False,
                local_rpe_id="rpe-1",
                listen_host="127.0.0.1",
                listen_port=0,
                peer_addresses={},
                echo_timeout_sec=2,
                recovery_timeout_sec=2,
                expt_cache_path=os.path.join(temp_dir, "expt.json"),
                counter_cache_path=os.path.join(temp_dir, "counter.json"),
                ft_quorum=1,
            )
            manager = FTControlManager(
                config,
                private_key,
                self._pem(public_key),
                {"rpe-1": self._pem(public_key)},
            )
            mock_channel = MagicMock()
            mock_rpc = MagicMock(return_value=b"{\"status\": 0}")
            mock_channel.unary_unary.return_value = mock_rpc
            with patch(
                "RPE.relying_party_enclave.ft_control.grpc.insecure_channel",
                return_value=mock_channel,
            ) as insecure_channel:
                address = "127.0.0.1:56001"
                manager.grpc_post_json(address, "StateUpdate", {"status": 0}, 1.0)
                manager.grpc_post_json(address, "RecoveryQuery", {"status": 0}, 1.0)
                insecure_channel.assert_called_once()


    def test_grpc_channel_pool_evicts_on_rpc_failure(self):
        from unittest.mock import MagicMock, patch

        with tempfile.TemporaryDirectory() as temp_dir:
            private_key, public_key = self._key_pair()
            config = FTConfig(
                enabled=False,
                local_rpe_id="rpe-1",
                listen_host="127.0.0.1",
                listen_port=0,
                peer_addresses={},
                echo_timeout_sec=2,
                recovery_timeout_sec=2,
                expt_cache_path=os.path.join(temp_dir, "expt.json"),
                counter_cache_path=os.path.join(temp_dir, "counter.json"),
                ft_quorum=1,
            )
            manager = FTControlManager(
                config,
                private_key,
                self._pem(public_key),
                {"rpe-1": self._pem(public_key)},
            )
            first_channel = MagicMock()
            second_channel = MagicMock()
            failing_rpc = MagicMock(side_effect=RuntimeError("rpc failed"))
            succeeding_rpc = MagicMock(return_value=b"{\"status\": 0}")
            first_channel.unary_unary.return_value = failing_rpc
            second_channel.unary_unary.return_value = succeeding_rpc
            with patch(
                "RPE.relying_party_enclave.ft_control.grpc.insecure_channel",
                side_effect=[first_channel, second_channel],
            ) as insecure_channel:
                address = "127.0.0.1:56001"
                with self.assertRaises(RuntimeError):
                    manager.grpc_post_json(address, "Ping", {"status": 0}, 1.0)
                first_channel.close.assert_called_once()
                response = manager.grpc_post_json(address, "Ping", {"status": 0}, 1.0)
                self.assertEqual(response["status"], 0)
                self.assertEqual(insecure_channel.call_count, 2)

    def test_public_key_cache_avoids_repeated_pem_parsing(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as temp_dir:
            private_key, public_key = self._key_pair()
            pem = self._pem(public_key)
            config = FTConfig(
                enabled=False,
                local_rpe_id="rpe-1",
                listen_host="127.0.0.1",
                listen_port=0,
                peer_addresses={},
                echo_timeout_sec=2,
                recovery_timeout_sec=2,
                expt_cache_path=os.path.join(temp_dir, "expt.json"),
                counter_cache_path=os.path.join(temp_dir, "counter.json"),
                ft_quorum=1,
            )
            manager = FTControlManager(
                config,
                private_key,
                pem,
                {"rpe-2": pem},
            )
            call_count = {"n": 0}
            real_load = __import__(
                "RPE.relying_party_enclave.ft_control", fromlist=["load_public_key_pem"]
            ).load_public_key_pem

            def counting_load(pem_data):
                call_count["n"] += 1
                return real_load(pem_data)

            with patch(
                "RPE.relying_party_enclave.ft_control.load_public_key_pem",
                side_effect=counting_load,
            ):
                key_a = manager._peer_public_key("rpe-2")
                key_b = manager._peer_public_key("rpe-2")
            self.assertIs(key_a, key_b)
            self.assertEqual(call_count["n"], 1)


if __name__ == "__main__":
    unittest.main()
