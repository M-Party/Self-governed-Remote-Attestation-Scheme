import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "RPE" / "relying_party_enclave"))

from policies import Policies  # noqa: E402


def test_template_ce_tcb_and_connection_ce_refs():
    template = json.loads((ROOT / "RPO" / "policies.json.template").read_text())
    assert "tcb_allowed" not in template["job"][0]
    assert template["ce"][0]["tcb_allowed"] == ["tcb-1"]
    assert template["connection"][0]["server"] == "ce-1"
    p = Policies(template)
    assert p.getCETcbIds("rpe-1") == ["tcb-1"]
    assert p.getCorrespondingJobs("job-1")[0]["jobs"] == ["job-2"]


def test_legacy_job_tcb_fallback():
    template = json.loads((ROOT / "RPO" / "policies.json.template").read_text())
    template["ce"][0].pop("tcb_allowed")
    template["job"][0]["tcb_allowed"] = ["tcb-2"]
    p = Policies(template)
    assert p.getCETCBINFO("job-1") == [template["tcb"][1]["data"]]
