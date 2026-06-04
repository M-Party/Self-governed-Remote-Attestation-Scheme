import os
import configparser
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
                        "signature": sign_json(
                            sender_private,
                            {
                                "target_rpe_id": "rpe-1",
                                "tee_id": "ce-1",
                                "attestation_counter": 1,
                                "nonce": "grpc-nonce",
                            },
                        ),
                    },
                    2,
                )
                self.assertEqual(response["status"], 0)
                self.assertEqual(response["echo"]["responder_rpe_id"], "rpe-2")
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
            self.assertEqual(echoes, [])
            self.assertEqual(manager.state_store.next_local_counter("ce-1"), 2)

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
                "state": dict(state),
                "signature": "not-base64",
            }
            self.assertEqual(receiver.handle_state_update(bad_update)["status"], 1)

            good_update = {
                "sender_rpe_id": "rpe-1",
                "state": dict(state),
                "signature": sign_json(sender_private, state),
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
            setup = MultiPartySetup(base_dir=root, num_parties=2, ft_enabled=True, ft_base_port=56001)
            setup.setup_multiple_parties()
            cfg = configparser.ConfigParser()
            cfg.read(os.path.join(root, "RPE_party1/config.toml"))
            self.assertEqual(cfg["ft"]["enabled"], "true")
            self.assertEqual(cfg["ft"]["listen_port"].strip('"'), "56001")
            self.assertIn("rpe-2=127.0.0.1:56002", cfg["ft"]["peer_addresses"])


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
            self.assertEqual(response["status"], 1)

    def test_recovery_query_returns_generated_evidence_quote_and_signed_state(self):
        class FakeQuoteProvider:
            def generate_evidence_quote(self, nonce):
                return {
                    "evidence_quote": "quote-for-" + nonce,
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
            self.assertEqual(response["evidence_quote"], "quote-for-recovery-nonce")
            self.assertEqual(response["rpe_public_signing_key"], "signing-key")
            self.assertEqual(response["rpe_public_encryption_key"], "encryption-key")
            self.assertEqual(
                response["signed_state"]["state"]["recorded_attestation_state"], state
            )
            self.assertEqual(response["signed_state"]["state"]["recovery_nonce"], "recovery-nonce")

    def test_recover_local_counter_from_latest_valid_grpc_response(self):
        class FakeQuoteProvider:
            def __init__(self):
                self.verified = []

            def verify_evidence_quote(self, evidence_quote, signing_key_pem, encryption_key_pem, expt_hash, nonce):
                self.verified.append((evidence_quote, signing_key_pem, encryption_key_pem, expt_hash, nonce))
                return evidence_quote.startswith("quote-") and nonce == "fixed-nonce"

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
                def generate_evidence_quote(self, nonce):
                    return {
                        "evidence_quote": "quote-" + nonce,
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
                "signature": sign_json(recovering_private, state),
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

    def test_broadcast_evidence_update_uses_grpc_and_waits_for_quorum(self):
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
                ok, peers = recovering.broadcast_evidence_update({
                    "evidence_quote": "fresh-quote",
                    "rpe_public_signing_key": self._pem(new_public),
                    "rpe_public_encryption_key": "new-encryption-key",
                    "expt_hash": "hash-a",
                })
                self.assertTrue(ok)
                self.assertEqual(peers, ["rpe-2"])
                self.assertEqual(peer.peer_public_keys["rpe-1"], self._pem(new_public))
                self.assertEqual(updated_keys, [("rpe-1", self._pem(new_public), "new-encryption-key")])
            finally:
                peer.stop()

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


if __name__ == "__main__":
    unittest.main()
