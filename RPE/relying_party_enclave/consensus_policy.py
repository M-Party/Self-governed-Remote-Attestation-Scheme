"""Consensus expectation policy: canonicalize, hash, join (τ/ι/β)."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import logging
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

logger = logging.getLogger(__name__)

STATUS_ORDER = {
    "OutOfDate": 0,
    "ConfigurationNeeded": 1,
    "UpToDate": 2,
}

CONSENSUS_TOP_KEYS = ("tcb", "rpe", "ce", "job")


class JoinError(Exception):
    """Negotiation failure (⊥) or TCB FMSPC legality failure during join."""

    def __init__(
        self,
        component: str,
        entity: str,
        field: Optional[str] = None,
        value_a: Any = None,
        value_b: Any = None,
    ):
        self.component = component
        self.entity = entity
        self.field = field
        self.value_a = value_a
        self.value_b = value_b
        super().__init__(self.to_dict())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "component": self.component,
            "entity": self.entity,
            "field": self.field,
            "value_a": self.value_a,
            "value_b": self.value_b,
        }

    def __str__(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, ensure_ascii=False)


def sha384_digest(data: bytes) -> bytes:
    return hashlib.sha384(data).digest()


def sha384_hex(data: bytes) -> str:
    return hashlib.sha384(data).hexdigest()


def content_address_tcb_id(collateral: str, min_status: str) -> str:
    payload = (collateral or "").encode("utf-8") + (min_status or "").encode("utf-8")
    return "tcb-" + sha384_hex(payload)[:16]


def extract_eval_number(tcb_entry: Dict[str, Any]) -> int:
    if "tcbEvaluationDataNumber" in tcb_entry:
        return int(tcb_entry["tcbEvaluationDataNumber"])
    data = tcb_entry.get("data")
    if isinstance(data, dict):
        if "tcbEvaluationDataNumber" in data:
            return int(data["tcbEvaluationDataNumber"])
    if isinstance(data, str) and data:
        # Try JSON string, then base64(JSON)
        for candidate in (data,):
            try:
                parsed = json.loads(candidate)
                if isinstance(parsed, dict) and "tcbEvaluationDataNumber" in parsed:
                    return int(parsed["tcbEvaluationDataNumber"])
            except (TypeError, ValueError, json.JSONDecodeError):
                pass
        try:
            raw = base64.b64decode(data, validate=False)
            parsed = json.loads(raw.decode("utf-8"))
            if isinstance(parsed, dict) and "tcbEvaluationDataNumber" in parsed:
                return int(parsed["tcbEvaluationDataNumber"])
        except Exception:
            pass
    return 0


def build_evidence_report_data(pk_s_pem: str, policy_hash: bytes) -> bytes:
    """SGX report_data (64B): SHA384(PK_s ‖ H(ρ)) ‖ 0x00*16."""
    if not isinstance(policy_hash, (bytes, bytearray)):
        raise TypeError("policy_hash must be bytes")
    if len(policy_hash) != 48:
        raise ValueError("policy_hash must be SHA-384 digest (48 bytes)")
    pk = pk_s_pem if isinstance(pk_s_pem, str) else pk_s_pem.decode("utf-8")
    inner = sha384_digest(pk.encode("utf-8") + bytes(policy_hash))
    return inner + (b"\x00" * 16)


def _require_single_tcb_allowed(entity_id: str, tcb_allowed: Any, where: str) -> str:
    if not isinstance(tcb_allowed, list) or len(tcb_allowed) != 1:
        raise JoinError(
            "input",
            entity_id,
            field="tcb_allowed",
            value_a=tcb_allowed,
            value_b="len==1 required",
        )
    entry_id = tcb_allowed[0]
    if not isinstance(entry_id, str) or not entry_id:
        raise JoinError(
            "input",
            entity_id,
            field="tcb_allowed",
            value_a=tcb_allowed,
            value_b="non-empty string id",
        )
    return entry_id


def _tcb_by_id(policy: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for item in policy.get("tcb") or []:
        out[item["id"]] = item
    return out


def rewrite_tcb_content_ids(policy: Dict[str, Any]) -> Dict[str, Any]:
    """Return a deep copy with TCB ids rewritten to content-addressed form."""
    p = copy.deepcopy(policy)
    old_to_new: Dict[str, str] = {}
    new_tcb: Dict[str, Dict[str, Any]] = {}
    for item in p.get("tcb") or []:
        if "min_status" not in item:
            raise JoinError("input", item.get("id", "?"), field="min_status", value_a=None, value_b="required")
        if "fmspc" not in item or not item["fmspc"]:
            raise JoinError("input", item.get("id", "?"), field="fmspc", value_a=item.get("fmspc"), value_b="required")
        new_id = content_address_tcb_id(item.get("data", ""), item["min_status"])
        old_to_new[item["id"]] = new_id
        rewritten = dict(item)
        rewritten["id"] = new_id
        if new_id in new_tcb and (
            new_tcb[new_id].get("data") != rewritten.get("data")
            or new_tcb[new_id].get("min_status") != rewritten.get("min_status")
            or new_tcb[new_id].get("fmspc") != rewritten.get("fmspc")
        ):
            # Same content id must be identical; ignore duplicates if equal
            pass
        new_tcb[new_id] = rewritten
    p["tcb"] = [new_tcb[k] for k in sorted(new_tcb.keys())]

    for rpe in p.get("rpe") or []:
        old = _require_single_tcb_allowed(rpe["id"], rpe.get("tcb_allowed"), "rpe")
        if old not in old_to_new:
            raise JoinError("input", rpe["id"], field="tcb_allowed", value_a=old, value_b="missing tcb entry")
        rpe["tcb_allowed"] = [old_to_new[old]]

    for ce in p.get("ce") or []:
        old = _require_single_tcb_allowed(ce["id"], ce.get("tcb_allowed"), "ce")
        if old not in old_to_new:
            raise JoinError("input", ce["id"], field="tcb_allowed", value_a=old, value_b="missing tcb entry")
        ce["tcb_allowed"] = [old_to_new[old]]

    # job must not carry tcb_allowed in new semantics
    for job in p.get("job") or []:
        if "tcb_allowed" in job:
            logger.warning(
                "policy job %s still has tcb_allowed; ignored for consensus (use ce.tcb_allowed)",
                job.get("id"),
            )
            job.pop("tcb_allowed", None)

    return p


def _identity_field_view(ce: Dict[str, Any], field: str) -> Tuple[str, Any]:
    """Return (kind, value) for one identity dimension."""
    if field == "mrenclave":
        if ce.get("mrenclave_allow_any") is True:
            return ("any", None)
        if "mrenclave" in ce:
            return ("exact", str(ce["mrenclave"]).lower())
        return ("any", None)
    if field == "mrsigner":
        if ce.get("mrsigner_allow_any") is True:
            return ("any", None)
        if "mrsigner" in ce:
            return ("exact", str(ce["mrsigner"]).lower())
        return ("any", None)
    if field == "isv_prod_id":
        if ce.get("isvprodid_allow_any") is True:
            return ("any", None)
        if "isv_prod_id" in ce:
            return ("exact", str(ce["isv_prod_id"]))
        return ("any", None)
    if field == "isv_svn":
        if ce.get("isvsvn_allow_any") is True:
            return ("any", None)
        if "isvsvn_minimum" in ce:
            return ("min", int(ce["isvsvn_minimum"]))
        if "isv_svn" in ce:
            # Exact SVN treated as Min(exact) for join strength (accept >= exact)
            return ("min", int(ce["isv_svn"]))
        return ("any", None)
    raise ValueError(field)


def _join_identity_field(entity: str, field: str, a: Tuple[str, Any], b: Tuple[str, Any]) -> Tuple[str, Any]:
    if a[0] == "any":
        return b
    if b[0] == "any":
        return a
    if a[0] == "exact" and b[0] == "exact":
        if a[1] == b[1]:
            return a
        raise JoinError("identity", entity, field=field, value_a=a[1], value_b=b[1])
    if a[0] == "min" and b[0] == "min":
        return ("min", max(int(a[1]), int(b[1])))
    # exact ⊔ min is not in SPEC primary matrix; treat as conflict if incompatible
    raise JoinError("identity", entity, field=field, value_a=list(a), value_b=list(b))


def _apply_identity_field(ce: Dict[str, Any], field: str, joined: Tuple[str, Any]) -> None:
    kind, value = joined
    if field == "mrenclave":
        ce.pop("mrenclave", None)
        ce.pop("mrenclave_allow_any", None)
        if kind == "any":
            ce["mrenclave_allow_any"] = True
        else:
            ce["mrenclave"] = value
    elif field == "mrsigner":
        ce.pop("mrsigner", None)
        ce.pop("mrsigner_allow_any", None)
        if kind == "any":
            ce["mrsigner_allow_any"] = True
        else:
            ce["mrsigner"] = value
    elif field == "isv_prod_id":
        ce.pop("isv_prod_id", None)
        ce.pop("isvprodid_allow_any", None)
        if kind == "any":
            ce["isvprodid_allow_any"] = True
        else:
            ce["isv_prod_id"] = value
    elif field == "isv_svn":
        ce.pop("isv_svn", None)
        ce.pop("isvsvn_allow_any", None)
        ce.pop("isvsvn_minimum", None)
        if kind == "any":
            ce["isvsvn_allow_any"] = True
        else:
            ce["isvsvn_minimum"] = int(value)


def _stronger_tcb(entry_a: Dict[str, Any], entry_b: Dict[str, Any], entity: str) -> Dict[str, Any]:
    fmspc_a = entry_a.get("fmspc")
    fmspc_b = entry_b.get("fmspc")
    if fmspc_a != fmspc_b:
        raise JoinError(
            "tcb_fmspc",
            entity,
            field="fmspc",
            value_a=fmspc_a,
            value_b=fmspc_b,
        )
    sa = entry_a.get("min_status", "OutOfDate")
    sb = entry_b.get("min_status", "OutOfDate")
    if sa not in STATUS_ORDER or sb not in STATUS_ORDER:
        raise JoinError("input", entity, field="min_status", value_a=sa, value_b=sb)
    if STATUS_ORDER[sa] > STATUS_ORDER[sb]:
        return entry_a
    if STATUS_ORDER[sb] > STATUS_ORDER[sa]:
        return entry_b
    ea = extract_eval_number(entry_a)
    eb = extract_eval_number(entry_b)
    if ea >= eb:
        return entry_a
    return entry_b


def _ce_index(policy: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {ce["id"]: ce for ce in (policy.get("ce") or [])}


def _rpe_index(policy: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {rpe["id"]: rpe for rpe in (policy.get("rpe") or [])}


def _jobs_as_pairs(policy: Dict[str, Any]) -> Dict[Tuple[str, str], str]:
    """Map (rpe, ce) -> job id (lexicographically smallest on conflict of ids)."""
    pairs: Dict[Tuple[str, str], str] = {}
    for job in policy.get("job") or []:
        key = (job["rpe"], job["ce"])
        jid = job.get("id") or f"job-{job['rpe']}-{job['ce']}"
        if key not in pairs or jid < pairs[key]:
            pairs[key] = jid
    return pairs


def join_policies(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """Join two expectation policies into π (or raise JoinError)."""
    ca = rewrite_tcb_content_ids(a)
    cb = rewrite_tcb_content_ids(b)

    tcb_map: Dict[str, Dict[str, Any]] = {}
    for src in (ca, cb):
        for item in src.get("tcb") or []:
            tcb_map[item["id"]] = item

    # τ on rpe + ce
    rpe_ids = sorted(set(_rpe_index(ca)) | set(_rpe_index(cb)))
    out_rpe: List[Dict[str, Any]] = []
    for rid in rpe_ids:
        assigns = []
        for src in (ca, cb):
            idx = _rpe_index(src)
            if rid in idx:
                tid = idx[rid]["tcb_allowed"][0]
                assigns.append(tcb_map[tid])
        if not assigns:
            continue
        chosen = assigns[0]
        for other in assigns[1:]:
            chosen = _stronger_tcb(chosen, other, rid)
        # Preserve non-consensus eng fields from lexicographically first source that has them
        eng = {}
        for src in (ca, cb):
            idx = _rpe_index(src)
            if rid in idx:
                for k, v in idx[rid].items():
                    if k in ("id", "tcb_allowed"):
                        continue
                    eng.setdefault(k, v)
        out_rpe.append({"id": rid, "tcb_allowed": [chosen["id"]], **eng})

    ce_ids = sorted(set(_ce_index(ca)) | set(_ce_index(cb)))
    out_ce: List[Dict[str, Any]] = []
    for cid in ce_ids:
        sources = [idx[cid] for idx in (_ce_index(ca), _ce_index(cb)) if cid in idx]
        # τ
        assigns = [tcb_map[s["tcb_allowed"][0]] for s in sources]
        chosen = assigns[0]
        for other in assigns[1:]:
            chosen = _stronger_tcb(chosen, other, cid)
        # ι
        joined_ce: Dict[str, Any] = {"id": cid, "tcb_allowed": [chosen["id"]]}
        for field in ("mrenclave", "mrsigner", "isv_prod_id", "isv_svn"):
            views = [_identity_field_view(s, field) for s in sources]
            acc = views[0]
            for nxt in views[1:]:
                acc = _join_identity_field(cid, field, acc, nxt)
            _apply_identity_field(joined_ce, field, acc)
        # eng / qeid: first-seen
        for s in sources:
            for k, v in s.items():
                if k in joined_ce or k in (
                    "id",
                    "tcb_allowed",
                    "mrenclave",
                    "mrenclave_allow_any",
                    "mrsigner",
                    "mrsigner_allow_any",
                    "isv_prod_id",
                    "isvprodid_allow_any",
                    "isv_svn",
                    "isvsvn_allow_any",
                    "isvsvn_minimum",
                ):
                    continue
                joined_ce.setdefault(k, v)
        out_ce.append(joined_ce)

    # β
    pairs = _jobs_as_pairs(ca)
    for key, jid in _jobs_as_pairs(cb).items():
        if key not in pairs or jid < pairs[key]:
            pairs[key] = jid
    ce_to_rpes: Dict[str, set] = {}
    for (rpe_id, ce_id), _ in pairs.items():
        ce_to_rpes.setdefault(ce_id, set()).add(rpe_id)
    for ce_id, rpes in ce_to_rpes.items():
        if len(rpes) > 1:
            raise JoinError(
                "attester",
                ce_id,
                field="rpe",
                value_a=sorted(rpes)[0],
                value_b=sorted(rpes)[1] if len(rpes) > 1 else None,
            )

    # Preserve eng-only job fields (e.g. cust_qeid_allowed) from first-seen source
    job_eng: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for src in (ca, cb):
        for job in src.get("job") or []:
            key = (job["rpe"], job["ce"])
            eng = {k: v for k, v in job.items() if k not in ("id", "rpe", "ce", "tcb_allowed")}
            if key not in job_eng:
                job_eng[key] = eng
            else:
                for k, v in eng.items():
                    job_eng[key].setdefault(k, v)
    out_jobs = []
    for (r, c) in sorted(pairs.keys(), key=lambda x: (x[0], x[1])):
        item = {"id": pairs[(r, c)], "rpe": r, "ce": c}
        item.update(job_eng.get((r, c), {}))
        out_jobs.append(item)

    # Keep referenced TCB entries (+ optionally unused from union — keep full union)
    out = {
        "tcb": [tcb_map[k] for k in sorted(tcb_map.keys())],
        "rpe": out_rpe,
        "ce": out_ce,
        "job": out_jobs,
    }
    return out


def compute_consensus(policies: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    if not policies:
        raise ValueError("compute_consensus requires at least one policy")
    acc = rewrite_tcb_content_ids(policies[0])
    # Normalize first alone through join with itself for consistent shape
    acc = join_policies(acc, acc)
    for other in policies[1:]:
        acc = join_policies(acc, other)
    return acc


def consensus_view(policy: Dict[str, Any]) -> Dict[str, Any]:
    """Strip non-consensus / eng-only fields for hashing."""
    p = rewrite_tcb_content_ids(policy)
    view: Dict[str, Any] = {"tcb": [], "rpe": [], "ce": [], "job": []}
    for item in p.get("tcb") or []:
        view["tcb"].append(
            {
                "id": item["id"],
                "fmspc": item["fmspc"],
                "min_status": item["min_status"],
                "data": item.get("data", ""),
                "tcbEvaluationDataNumber": extract_eval_number(item),
            }
        )
    view["tcb"].sort(key=lambda x: x["id"])
    for rpe in p.get("rpe") or []:
        view["rpe"].append({"id": rpe["id"], "tcb_allowed": list(rpe["tcb_allowed"])})
    view["rpe"].sort(key=lambda x: x["id"])
    for ce in p.get("ce") or []:
        entry: Dict[str, Any] = {"id": ce["id"], "tcb_allowed": list(ce["tcb_allowed"])}
        for field in ("mrenclave", "mrsigner", "isv_prod_id", "isv_svn"):
            kind, value = _identity_field_view(ce, field)
            if field == "mrenclave":
                if kind == "any":
                    entry["mrenclave_allow_any"] = True
                else:
                    entry["mrenclave"] = value
            elif field == "mrsigner":
                if kind == "any":
                    entry["mrsigner_allow_any"] = True
                else:
                    entry["mrsigner"] = value
            elif field == "isv_prod_id":
                if kind == "any":
                    entry["isvprodid_allow_any"] = True
                else:
                    entry["isv_prod_id"] = value
            elif field == "isv_svn":
                if kind == "any":
                    entry["isvsvn_allow_any"] = True
                else:
                    entry["isvsvn_minimum"] = int(value)
        view["ce"].append(entry)
    view["ce"].sort(key=lambda x: x["id"])
    for job in p.get("job") or []:
        view["job"].append({"id": job["id"], "rpe": job["rpe"], "ce": job["ce"]})
    view["job"].sort(key=lambda x: (x["rpe"], x["ce"], x["id"]))
    return view


def canonicalize_policy(policy: Dict[str, Any]) -> bytes:
    view = consensus_view(policy)
    return json.dumps(view, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def hash_policy(policy: Dict[str, Any]) -> bytes:
    return sha384_digest(canonicalize_policy(policy))


def hash_policy_hex(policy: Dict[str, Any]) -> str:
    return sha384_hex(canonicalize_policy(policy))
