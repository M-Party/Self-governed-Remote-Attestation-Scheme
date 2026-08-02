import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "RPE" / "relying_party_enclave"))

from consensus_policy import (  # noqa: E402
    JoinError,
    build_evidence_report_data,
    canonicalize_policy,
    compute_consensus,
    content_address_tcb_id,
    hash_policy,
    hash_policy_hex,
    join_policies,
)


def _tcb(tid, fmspc, min_status, eval_n, data=None):
    if data is None:
        data = json.dumps({"tcbEvaluationDataNumber": eval_n, "payload": tid})
    return {
        "id": tid,
        "fmspc": fmspc,
        "min_status": min_status,
        "data": data,
        "tcbEvaluationDataNumber": eval_n,
    }


def base_policy():
    return {
        "session_id": "s1",
        "description": "test",
        "rpe_info": {"mrenclave": "aa", "mrsigner": "bb", "isv_prod_id": "0", "isv_svn": "0"},
        "tcb": [
            _tcb("tcb-1", "FMSPC-A", "UpToDate", 10),
            _tcb("tcb-2", "FMSPC-A", "ConfigurationNeeded", 5),
        ],
        "rpe": [
            {
                "id": "rpe-1",
                "tcb_allowed": ["tcb-1"],
                "qeid_allowed": ["qe1"],
                "ca_signing_key_cert": "PEM1",
            },
            {
                "id": "rpe-2",
                "tcb_allowed": ["tcb-2"],
                "qeid_allowed": ["qe1"],
                "ca_signing_key_cert": "PEM2",
            },
        ],
        "ce": [
            {
                "id": "ce-1",
                "mrenclave": "abcd",
                "mrsigner_allow_any": True,
                "isvprodid_allow_any": True,
                "isvsvn_allow_any": True,
                "tcb_allowed": ["tcb-1"],
            },
            {
                "id": "ce-2",
                "mrenclave_allow_any": True,
                "mrsigner": "signer2",
                "isv_prod_id": "42",
                "isvsvn_minimum": 3,
                "tcb_allowed": ["tcb-2"],
            },
        ],
        "job": [
            {"id": "job-1", "rpe": "rpe-1", "ce": "ce-1"},
            {"id": "job-2", "rpe": "rpe-2", "ce": "ce-2"},
        ],
        "connection": [{"id": "c1", "server": "ce-1", "clients": ["ce-2"]}],
    }


def test_content_address_deterministic():
    a = content_address_tcb_id("data", "UpToDate")
    b = content_address_tcb_id("data", "UpToDate")
    assert a == b
    assert a.startswith("tcb-")
    assert len(a) == 4 + 16


def test_canonicalize_order_independent():
    p1 = base_policy()
    p2 = copy.deepcopy(p1)
    p2["tcb"] = list(reversed(p2["tcb"]))
    p2["rpe"] = list(reversed(p2["rpe"]))
    p2["ce"] = list(reversed(p2["ce"]))
    p2["job"] = list(reversed(p2["job"]))
    assert canonicalize_policy(p1) == canonicalize_policy(p2)
    assert hash_policy_hex(p1) == hash_policy_hex(p2)


def test_report_data_is_64_bytes_and_binds_full_policy_hash():
    h = hash_policy(base_policy())
    rd = build_evidence_report_data("-----BEGIN PUBLIC KEY-----\nX\n-----END PUBLIC KEY-----", h)
    assert len(rd) == 64
    assert rd[48:] == b"\x00" * 16


def test_identity_any_join_exact():
    a = base_policy()
    b = base_policy()
    b["ce"][0] = {
        "id": "ce-1",
        "mrenclave_allow_any": True,
        "mrsigner_allow_any": True,
        "isvprodid_allow_any": True,
        "isvsvn_allow_any": True,
        "tcb_allowed": ["tcb-1"],
    }
    # a has exact mrenclave, b any → exact
    pi = join_policies(a, b)
    ce1 = next(c for c in pi["ce"] if c["id"] == "ce-1")
    assert ce1["mrenclave"] == "abcd"
    assert "mrenclave_allow_any" not in ce1


def test_identity_exact_conflict():
    a = base_policy()
    b = base_policy()
    b["ce"][0]["mrenclave"] = "ffff"
    with pytest.raises(JoinError) as ei:
        join_policies(a, b)
    assert ei.value.component == "identity"
    assert ei.value.field == "mrenclave"


def test_identity_min_svn_takes_max():
    a = base_policy()
    b = base_policy()
    b["ce"][1]["isvsvn_minimum"] = 7
    pi = join_policies(a, b)
    ce2 = next(c for c in pi["ce"] if c["id"] == "ce-2")
    assert ce2["isvsvn_minimum"] == 7


def test_tau_higher_status_wins():
    a = base_policy()
    b = base_policy()
    # same fmspc, raise status on tcb-2 path for rpe-2 in b via new entry
    b["tcb"].append(_tcb("tcb-2b", "FMSPC-A", "UpToDate", 1))
    b["rpe"][1]["tcb_allowed"] = ["tcb-2b"]
    pi = join_policies(a, b)
    rpe2 = next(r for r in pi["rpe"] if r["id"] == "rpe-2")
    # UpToDate from b should win over ConfigurationNeeded from a
    chosen = next(t for t in pi["tcb"] if t["id"] == rpe2["tcb_allowed"][0])
    assert chosen["min_status"] == "UpToDate"


def test_tau_eval_number_tiebreak_same_fmspc():
    a = base_policy()
    b = base_policy()
    b["tcb"] = [
        _tcb("tcb-1", "FMSPC-A", "UpToDate", 99),
        _tcb("tcb-2", "FMSPC-A", "ConfigurationNeeded", 5),
    ]
    # rewrite ids by content — different eval number ⇒ different content id if data differs
    pi = join_policies(a, b)
    rpe1 = next(r for r in pi["rpe"] if r["id"] == "rpe-1")
    chosen = next(t for t in pi["tcb"] if t["id"] == rpe1["tcb_allowed"][0])
    assert chosen["tcbEvaluationDataNumber"] == 99 or (
        json.loads(chosen["data"])["tcbEvaluationDataNumber"] == 99
    )


def test_tau_cross_fmspc_join_error():
    a = base_policy()
    b = base_policy()
    b["tcb"][0]["fmspc"] = "FMSPC-OTHER"
    # Keep same data/min_status so content id may collide — force different data so both exist,
    # but same entity points to different fmspc entries
    b["tcb"][0]["data"] = json.dumps({"tcbEvaluationDataNumber": 10, "payload": "other"})
    with pytest.raises(JoinError) as ei:
        join_policies(a, b)
    assert ei.value.component == "tcb_fmspc"


def test_tcb_allowed_must_be_single():
    a = base_policy()
    a["rpe"][0]["tcb_allowed"] = ["tcb-1", "tcb-2"]
    with pytest.raises(JoinError) as ei:
        join_policies(a, a)
    assert ei.value.component == "input"
    assert ei.value.field == "tcb_allowed"


def test_beta_union_and_attester_conflict():
    a = base_policy()
    b = base_policy()
    # union: b adds nothing new — ok
    pi = join_policies(a, b)
    assert len(pi["job"]) == 2

    b2 = base_policy()
    b2["job"] = [{"id": "job-x", "rpe": "rpe-1", "ce": "ce-2"}]  # ce-2 also attested by rpe-2 in a
    with pytest.raises(JoinError) as ei:
        join_policies(a, b2)
    assert ei.value.component == "attester"


def test_compute_consensus_order_independent():
    a = base_policy()
    b = base_policy()
    b["ce"][1]["isvsvn_minimum"] = 9
    h1 = hash_policy(compute_consensus([a, b]))
    h2 = hash_policy(compute_consensus([b, a]))
    assert h1 == h2


def test_join_error_serializable():
    err = JoinError("identity", "ce-1", field="mrenclave", value_a="a", value_b="b")
    d = err.to_dict()
    assert d["component"] == "identity"
    assert json.loads(str(err))["entity"] == "ce-1"
