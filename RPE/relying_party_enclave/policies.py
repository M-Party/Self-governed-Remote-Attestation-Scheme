import logging
import json
import os
import time
import ctypes

logger = logging.getLogger(__name__)

class Policies:
    def __init__(self, policies_data_json):
        self.policies_data_json = policies_data_json

    def _find_ce(self, ce_id):
        for ce in self.policies_data_json.get("ce") or []:
            if ce.get("id") == ce_id:
                return ce
        return None

    def _find_job(self, job_id):
        for job in self.policies_data_json.get("job") or []:
            if job.get("id") == job_id:
                return job
        return None

    def _job_ce_id(self, job_id):
        job = self._find_job(job_id)
        if job is None:
            return None
        return job.get("ce")

    def _tcb_ids_for_ce(self, ce_id, job=None):
        """Resolve CE tcb_allowed (new); fallback to job.tcb_allowed (legacy)."""
        ce = self._find_ce(ce_id)
        if ce is not None and ce.get("tcb_allowed") is not None:
            tcb_ids = ce.get("tcb_allowed")
            if not isinstance(tcb_ids, list) or len(tcb_ids) != 1:
                logger.warning(
                    "ce %s tcb_allowed should be a single-element list, got %s",
                    ce_id,
                    tcb_ids,
                )
            return tcb_ids
        if job is not None and job.get("tcb_allowed") is not None:
            logger.warning(
                "Using legacy job.tcb_allowed for ce %s; move to ce.tcb_allowed",
                ce_id,
            )
            return job.get("tcb_allowed")
        return None

    def _jobs_for_ce(self, ce_id):
        return [j for j in (self.policies_data_json.get("job") or []) if j.get("ce") == ce_id]


    def get_policies_data(self):
        policies_data_json = self.policies_data_json
        return json.dumps(policies_data_json)

    def getSesssionId(self):
        # Get session id from policies 
        logger.info("get session id from policies")
        policies_data_json = self.policies_data_json
        return policies_data_json["session_id"]
    
    def getPublicSigningKey(self, rpe_id):
        # Get public signing key from policies.json 
        logger.info("get public signing key from policies.json")
        policies_data_json = self.policies_data_json
        public_signing_key = None
        for rpe in policies_data_json["rpe"]:
            if rpe["id"] == rpe_id:
                public_signing_key = rpe["ca_signing_key_cert"]
                break
        if public_signing_key is None:
            logger.error("Cannot resolve public signing key of managed_rpe %s" % rpe_id)
            return None
        return public_signing_key

    def getRPEMR(self):
        # Get rpe mr from policies 
        logger.info("get rpe mr from policies")
        policies_data_json = self.policies_data_json
        return policies_data_json["rpe_info"]["mrenclave"]

    def getRPEMRSigner(self):
        # Get rpe mrsigner from policies 
        logger.info("get rpe mrsigner from policies")
        policies_data_json = self.policies_data_json
        return policies_data_json["rpe_info"]["mrsigner"]

    def getRPEISVProdID(self):
        # Get rpe isvproid from policies 
        logger.info("get rpe isvproid from policies")
        policies_data_json = self.policies_data_json
        return policies_data_json["rpe_info"]["isv_prod_id"]

    def getRPEISVSVN(self):
        # Get rpe isvsvn from policies 
        logger.info("get rpe isvsvn from policies")
        policies_data_json = self.policies_data_json
        return policies_data_json["rpe_info"]["isv_svn"]

    def getRPEQEID(self, rpe_id):
        # Get rpe qeid from policies 
        logger.info("get rpe qeid from policies")
        rpe_qeid = None
        policies_data_json = self.policies_data_json
        for rpe_item in policies_data_json["rpe"]:
            if rpe_item["id"] == rpe_id:
                rpe_qeid = rpe_item["qeid_allowed"]
                break
        if rpe_qeid is None:
            logger.error("Cannot resolve qeid of rpe")
            return None
        if not isinstance(rpe_qeid, list):
            logger.error("Format error in policies: Qeid of rpe, reqired list()")
            return rpe_qeid
        return rpe_qeid

    def getRPETCBInfo(self, rpe_id):
        # Get rpe tcb info from policies 
        logger.info("get rpe tcb info from policies")
        tcb_ids = None
        tcb_infos = dict()
        policies_data_json = self.policies_data_json
        
        # Find the tcb allowed of the rpe
        for rpe_item in policies_data_json["rpe"]:
            if rpe_item["id"] == rpe_id:
                tcb_ids = rpe_item["tcb_allowed"]
                break
        if tcb_ids is None:
            logger.error("Cannot resolve tcb_ids of rpe")
            return None
        
        # Get tcb infos
        for tcb_id in tcb_ids:
            tcb_info = None
            for tcb_item in policies_data_json["tcb"]:
                if tcb_item["id"] == tcb_id:
                    tcb_info = tcb_item["data"]
                    break
            if tcb_info is None:
                logger.error("Cannot resolve data of tcb: tcb_id %s" % tcb_id)
                return None
            tcb_infos[tcb_id] = tcb_info
        return tcb_ids, tcb_infos
    
    def getNumberOfRPE(self):
        # Get number of RPE from policies 
        logger.info("get number of rpe from policies")
        policies_data_json = self.policies_data_json
        return len(policies_data_json["rpe"])
    
    def getTcbIds(self):
        # Get all tcb id from policies 
        logger.info("get all tcb id from policies")
        policies_data_json = self.policies_data_json
        tcb_ids = list()
        for tcb in policies_data_json["tcb"]:
            tcb_ids.append(tcb["id"])
        return tcb_ids
    
    def getCETcbIds(self, rpe_id):
        # Get ce tcb id from policies (ce.tcb_allowed; legacy job.tcb_allowed)
        logger.info("get ce tcb id from policies")
        ce_tcb_ids = set()
        for job in self.policies_data_json["job"]:
            if job["rpe"] != rpe_id:
                continue
            tcb_ids = self._tcb_ids_for_ce(job["ce"], job=job)
            if not tcb_ids:
                logger.error("Cannot resolve tcb_ids of ce %s", job["ce"])
                continue
            for tcb_id in tcb_ids:
                ce_tcb_ids.add(tcb_id)
        return list(ce_tcb_ids)
    
    def checkTcbId(self, job_id, tcb_id):
        logger.info("check tcb id from policies")
        job = self._find_job(job_id)
        if job is None:
            return False
        tcb_ids = self._tcb_ids_for_ce(job["ce"], job=job) or []
        return tcb_id in tcb_ids
    
    def getCEMR(self, ce_id):
        # Get ce mr from policies 
        logger.info("get ce mr from policies")
        policies_data_json = self.policies_data_json
        mr_enclave = None
        for ce in policies_data_json["ce"]:
            if ce["id"] == ce_id:
                mr_enclave = ce["mrenclave"]
                break
        if mr_enclave is None:
            logger.error("Cannot resolve mrenclave of ce %s" % ce_id)
            return None
        return mr_enclave
    
    def getCEMRSigner(self, ce_id):
        # Get ce mr_signer from policies 
        logger.info("get ce mr_signer from policies")
        policies_data_json = self.policies_data_json
        mr_signer = None
        for ce in policies_data_json["ce"]:
            if ce["id"] == ce_id:
                mr_signer = ce["mrsigner"]
                break
        if mr_signer is None:
            logger.error("Cannot resolve mrsigner of ce %s" % ce_id)
            return None
        return mr_signer
    
    def getCEISVProdID(self, ce_id):
        # Get ce isv_prod_id from policies 
        logger.info("get ce isv_prod_id from policies")
        policies_data_json = self.policies_data_json
        isv_prod_id = None
        for ce in policies_data_json["ce"]:
            if ce["id"] == ce_id:
                isv_prod_id = ce["isv_prod_id"]
                break
        if isv_prod_id is None:
            logger.error("Cannot resolve isv_prod_id of ce %s" % ce_id)
            return None
        return isv_prod_id
    
    def getCEISVSVN(self, ce_id):
        # Get ce isv_svn from policies 
        logger.info("get ce isv_svn from policies")
        policies_data_json = self.policies_data_json
        isv_svn = None
        for ce in policies_data_json["ce"]:
            if ce["id"] == ce_id:
                isv_svn = ce["isv_svn"]
                break
        if isv_svn is None:
            logger.error("Cannot resolve isv_svn of ce %s" % ce_id)
            return None
        return isv_svn
    
    def getCorrespondingRPE(self, job_id):
        # Get ce isv_svn from policies 
        logger.info("get ce's corresponding rpe from policies")
        policies_data_json = self.policies_data_json
        rpe_id = None
        for job in policies_data_json["job"]:
            if job["id"] == job_id:
                rpe_id = job["rpe"]
                break
        if rpe_id is None:
            logger.error("Cannot resolve corresponding rpe_id of ce, job id is %s" % job_id)
            return None
        return rpe_id
    
    def getCEQEID(self, job_id):
        # Get ce qeid from policies (job.cust_qeid_allowed or ce.qeid_allowed)
        logger.info("get ce qeid from policies")
        job = self._find_job(job_id)
        if job is None:
            logger.error("Cannot resolve qeids of ce, job id is %s" % job_id)
            return None
        if job.get("cust_qeid_allowed") is not None:
            return job["cust_qeid_allowed"]
        ce = self._find_ce(job.get("ce"))
        if ce is not None and ce.get("qeid_allowed") is not None:
            return ce["qeid_allowed"]
        logger.error("Cannot resolve qeids of ce, job id is %s" % job_id)
        return None
    
    def getCETCBINFO(self, job_id):
        # Get ce tcb_info from policies (ce.tcb_allowed)
        logger.info("get ce tcb_info from policies")
        policies_data_json = self.policies_data_json
        job = self._find_job(job_id)
        if job is None:
            logger.error("Cannot resolve tcb_ids of ce, job id is %s" % job_id)
            return None
        tcb_ids = self._tcb_ids_for_ce(job["ce"], job=job)
        if tcb_ids is None:
            logger.error("Cannot resolve tcb_ids of ce, job id is %s" % job_id)
            return None

        tcb_infos = list()
        for tcb_id in tcb_ids:
            tcb_info = None
            for tcb_item in policies_data_json["tcb"]:
                if tcb_item["id"] == tcb_id:
                    tcb_info = tcb_item["data"]
                    break
            if tcb_info is None:
                logger.error("Cannot resolve data of tcb: tcb_id %s" % tcb_id)
                return None
            tcb_infos.append(tcb_info)
        return tcb_infos
    
    def getAllCEinfo(self):
        # Get all ce info from policies 
        logger.info("get all ce info from policies")
        policies_data_json = self.policies_data_json
        all_ce_info = dict()
        for job in policies_data_json["job"]:
            ce_id = job["ce"]
            ce_info = dict()
            ce_info["rpe"] = job["rpe"]
            qeids = job.get("cust_qeid_allowed")
            if qeids is None:
                ce_obj = self._find_ce(ce_id)
                qeids = (ce_obj or {}).get("qeid_allowed")
            ce_info["cust_qeid_allowed"] = qeids
            ce_info["tcb_allowed"] = self._tcb_ids_for_ce(ce_id, job=job)
            has_ce = False
            for ce in policies_data_json["ce"]:
                if ce["id"] == ce_id:
                    has_ce = True
                    if "mrenclave_allow_any" in ce.keys():
                        ce_info["mrenclave_allow_any"] = ce["mrenclave_allow_any"]
                    else:
                        ce_info["mrenclave"] = ce["mrenclave"]
                    if "mrsigner_allow_any" in ce.keys():
                        ce_info["mrsigner_allow_any"] = ce["mrsigner_allow_any"]
                    else:
                        ce_info["mrsigner"] = ce["mrsigner"]
                    if "isvprodid_allow_any" in ce.keys():
                        ce_info["isvprodid_allow_any"] = ce["isvprodid_allow_any"]
                    else:
                        ce_info["isv_prod_id"] = ce["isv_prod_id"]
                    if "isvsvn_allow_any" in ce.keys():
                        ce_info["isvsvn_allow_any"] = ce["isvsvn_allow_any"]
                    else:
                        ce_info["isv_svn"] = ce["isv_svn"]
                    break
            if not has_ce:
                logger.error("Cannot resolve ce %s" % ce_id)
                return None
            all_ce_info[job["id"]] = ce_info
        return all_ce_info
    
    def getCEsinfo(self, rpe_id):
        # Get ces' info from policies 
        logger.info("get ces' info from policies")
        policies_data_json = self.policies_data_json
        ces_info = dict()
        for job in policies_data_json["job"]:
            if job["rpe"] != rpe_id:
                continue
            ce_id = job["ce"]
            ce_info = dict()
            ce_info["rpe"] = job["rpe"]
            qeids = job.get("cust_qeid_allowed")
            if qeids is None:
                ce_obj = self._find_ce(ce_id)
                qeids = (ce_obj or {}).get("qeid_allowed")
            ce_info["cust_qeid_allowed"] = qeids
            ce_info["tcb_allowed"] = self._tcb_ids_for_ce(ce_id, job=job)
            has_ce = False
            for ce in policies_data_json["ce"]:
                if ce["id"] == ce_id:
                    has_ce = True
                    if "mrenclave_allow_any" in ce.keys():
                        ce_info["mrenclave_allow_any"] = ce["mrenclave_allow_any"]
                    else:
                        ce_info["mrenclave"] = ce["mrenclave"]
                    if "mrsigner_allow_any" in ce.keys():
                        ce_info["mrsigner_allow_any"] = ce["mrsigner_allow_any"]
                    else:
                        ce_info["mrsigner"] = ce["mrsigner"]
                    if "isvprodid_allow_any" in ce.keys():
                        ce_info["isvprodid_allow_any"] = ce["isvprodid_allow_any"]
                    else:
                        ce_info["isv_prod_id"] = ce["isv_prod_id"]
                    if "isvsvn_allow_any" in ce.keys():
                        ce_info["isvsvn_allow_any"] = ce["isvsvn_allow_any"]
                    else:
                        ce_info["isv_svn"] = ce["isv_svn"]
                    break
            if not has_ce:
                logger.error("Cannot resolve ce %s" % ce_id)
                return None
            ces_info[job["id"]] = ce_info
        return ces_info
    
    def getCEinfo(self, rpe_id, ce_id):
        # Get ces' info from policies 
        policies_data_json = self.policies_data_json
        ces_info = dict()
        for job in policies_data_json["job"]:
            if job["rpe"] != rpe_id or job["ce"] != ce_id:
                continue
            ce_info = dict()
            ce_info["rpe"] = job["rpe"]
            qeids = job.get("cust_qeid_allowed")
            if qeids is None:
                ce_obj = self._find_ce(ce_id)
                qeids = (ce_obj or {}).get("qeid_allowed")
            ce_info["cust_qeid_allowed"] = qeids
            ce_info["tcb_allowed"] = self._tcb_ids_for_ce(ce_id, job=job)
            has_ce = False
            for ce in policies_data_json["ce"]:
                if ce["id"] == ce_id:
                    has_ce = True
                    if "mrenclave_allow_any" in ce.keys():
                        ce_info["mrenclave_allow_any"] = ce["mrenclave_allow_any"]
                    else:
                        ce_info["mrenclave"] = ce["mrenclave"]
                    if "mrsigner_allow_any" in ce.keys():
                        ce_info["mrsigner_allow_any"] = ce["mrsigner_allow_any"]
                    else:
                        ce_info["mrsigner"] = ce["mrsigner"]
                    if "isvprodid_allow_any" in ce.keys():
                        ce_info["isvprodid_allow_any"] = ce["isvprodid_allow_any"]
                    else:
                        ce_info["isv_prod_id"] = ce["isv_prod_id"]
                    if "isvsvn_allow_any" in ce.keys():
                        ce_info["isvsvn_allow_any"] = ce["isvsvn_allow_any"]
                    else:
                        ce_info["isv_svn"] = ce["isv_svn"]
                    break
            if not has_ce:
                logger.error("Cannot resolve ce %s" % ce_id)
                return None
            ces_info[job["id"]] = ce_info
        return ces_info
    
    def getCorrespondingJobs(self, job_id):
        # connection refs are ce ids (new); legacy job ids still accepted
        logger.info("get corresponding jobs from policies")
        policies_data_json = self.policies_data_json
        local_ce = self._job_ce_id(job_id)
        jobs = list()
        for connection in policies_data_json["connection"]:
            job_dict = dict()
            peer_refs = list()
            server = connection["server"]
            clients = list(connection.get("clients") or [])
            # New semantics: match by ce id
            if local_ce is not None and server == local_ce:
                peer_refs += clients
            elif local_ce is not None and local_ce in clients:
                peer_refs.append(server)
            # Legacy: connection still points at job ids
            elif server == job_id:
                peer_refs += clients
            elif job_id in clients:
                peer_refs.append(server)

            peer_job_ids = []
            for ref in peer_refs:
                # ref may be ce id → expand to jobs; or already a job id
                mapped = [j["id"] for j in self._jobs_for_ce(ref)]
                if mapped:
                    peer_job_ids.extend(mapped)
                elif self._find_job(ref) is not None:
                    peer_job_ids.append(ref)
            # de-dup preserve order
            seen = set()
            ordered = []
            for jid in peer_job_ids:
                if jid not in seen and jid != job_id:
                    seen.add(jid)
                    ordered.append(jid)
            if ordered:
                job_dict["connection_id"] = connection["id"]
                job_dict["jobs"] = ordered
                jobs.append(job_dict)

        if len(jobs) == 0:
            logger.error("Cannot resolve any corresponding job id")
            return None
        return jobs
