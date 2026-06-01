import unittest

from RPE.relying_party_enclave.ft_control import FTConfig, derive_ft_quorum, parse_peer_addresses


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


if __name__ == "__main__":
    unittest.main()
