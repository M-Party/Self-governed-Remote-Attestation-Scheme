"""L1 smoke: sendPolicy/queryPolicyByIds over P2P quote channel."""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "RPE" / "relying_party_enclave"))
sys.path.insert(0, str(ROOT / "performance"))

import grpc_client  # noqa: E402
import consensus_policy  # noqa: E402


class PolicyExchangeP2PTest(unittest.TestCase):
    BASE_PORT = 61051
    NUM = 2

    @classmethod
    def setUpClass(cls):
        cls.procs = []
        script = ROOT / "performance" / "p2p_quote_exchange.py"
        for i in range(1, cls.NUM + 1):
            port = cls.BASE_PORT + i - 1
            peers = [
                "127.0.0.1:%d" % (cls.BASE_PORT + j - 1)
                for j in range(1, cls.NUM + 1)
                if j != i
            ]
            log_path = ROOT / "performance_data" / "logs" / ("l1_p2p_party%d.log" % i)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            lf = open(log_path, "w")
            p = subprocess.Popen(
                [
                    "python3",
                    str(script),
                    "--port",
                    str(port),
                    "--node-id",
                    "l1-party%d" % i,
                    "--peer-addresses",
                    ",".join(peers),
                    "--query-wait-timeout",
                    "5",
                ],
                cwd=str(ROOT),
                stdout=lf,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            cls.procs.append((p, lf))
        time.sleep(1.5)
        for p, _ in cls.procs:
            if p.poll() is not None:
                raise RuntimeError("P2P node exited early with %s" % p.returncode)

    @classmethod
    def tearDownClass(cls):
        for p, lf in cls.procs:
            try:
                p.terminate()
                p.wait(timeout=3)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
            try:
                lf.close()
            except Exception:
                pass

    def test_send_and_query_policies_roundtrip(self):
        addr1 = "127.0.0.1:%d" % self.BASE_PORT
        addr2 = "127.0.0.1:%d" % (self.BASE_PORT + 1)
        template = json.loads((ROOT / "RPO" / "policies.json.template").read_text())
        p1 = dict(template)
        p1["session_id"] = "l1-rpe-1"
        p2 = dict(template)
        p2["session_id"] = "l1-rpe-2"
        # diverge a consensus field so hashes differ
        p2["ce"] = json.loads(json.dumps(template["ce"]))
        p2["ce"][1]["isvsvn_minimum"] = 9

        h1 = consensus_policy.hash_policy_hex(p1)
        h2 = consensus_policy.hash_policy_hex(p2)
        self.assertNotEqual(h1, h2)

        b1 = base64.b64encode(
            json.dumps(p1, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        b2 = base64.b64encode(
            json.dumps(p2, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")

        self.assertTrue(grpc_client.sendPolicy(addr1, "rpe-1", b1))
        self.assertTrue(grpc_client.sendPolicy(addr2, "rpe-2", b2))

        # Query from the other node (after fanout)
        deadline = time.time() + 8
        got = {}
        while time.time() < deadline:
            ok, content = grpc_client.queryPolicyByIds(addr1, "rpe-1,rpe-2")
            self.assertTrue(ok)
            got = json.loads(content)
            if "rpe-1" in got and "rpe-2" in got:
                break
            time.sleep(0.2)
        self.assertIn("rpe-1", got)
        self.assertIn("rpe-2", got)

        raw1 = base64.b64decode(got["rpe-1"]).decode("utf-8")
        raw2 = base64.b64decode(got["rpe-2"]).decode("utf-8")
        back1 = json.loads(raw1)
        back2 = json.loads(raw2)
        self.assertEqual(consensus_policy.hash_policy_hex(back1), h1)
        self.assertEqual(consensus_policy.hash_policy_hex(back2), h2)

        # Quote channel must not see policies under bare rpe ids
        ok_q, qcontent = grpc_client.queryQuoteByIds(addr1, "rpe-1,rpe-2")
        self.assertTrue(ok_q)
        quotes = json.loads(qcontent)
        self.assertEqual(quotes, {})

        # Storage uses policy: prefix
        ok_p, pcontent = grpc_client.queryQuoteByIds(addr1, "policy:rpe-1,policy:rpe-2")
        self.assertTrue(ok_p)
        stored = json.loads(pcontent)
        self.assertIn("policy:rpe-1", stored)
        self.assertIn("policy:rpe-2", stored)

    def test_send_and_query_consensus_hash_roundtrip(self):
        addr1 = "127.0.0.1:%d" % self.BASE_PORT
        addr2 = "127.0.0.1:%d" % (self.BASE_PORT + 1)
        h = "ab" * 48
        self.assertTrue(grpc_client.sendConsensusHash(addr1, "rpe-1", h))
        self.assertTrue(grpc_client.sendConsensusHash(addr2, "rpe-2", h))
        deadline = time.time() + 8
        got = {}
        while time.time() < deadline:
            ok, content = grpc_client.queryConsensusHashByIds(addr1, "rpe-1,rpe-2")
            self.assertTrue(ok)
            got = json.loads(content)
            if "rpe-1" in got and "rpe-2" in got:
                break
            time.sleep(0.2)
        self.assertEqual(got.get("rpe-1"), h)
        self.assertEqual(got.get("rpe-2"), h)
        ok_q, qcontent = grpc_client.queryQuoteByIds(addr1, "hpi:rpe-1,hpi:rpe-2")
        self.assertTrue(ok_q)
        stored = json.loads(qcontent)
        self.assertIn("hpi:rpe-1", stored)
        self.assertIn("hpi:rpe-2", stored)



if __name__ == "__main__":
    unittest.main()
