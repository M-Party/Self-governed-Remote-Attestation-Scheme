import logging
import json
import ctypes
import os
import sys
import time
import threading
import hashlib
import grpc_client
import ft_control
from Cryptodome.Hash import SHA384
from ecdsa import SigningKey, VerifyingKey, NIST384p
from Cryptodome.PublicKey import RSA
from crypto_utils import crypto_utility
from quote_verification import verify_dcap_quote
import ratls
import certificate
from policies import Policies
import consensus_policy
from utility import config as pconfig
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends.openssl import backend as openssl_backend
from cryptography.exceptions import InvalidSignature

# Load .so
lib = ctypes.CDLL('./relying_party_enclave/keys_generation/generate_key_pair.so') 
# Define types of params and returns
lib.generate_rsa_keypair.argtypes = [ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_char_p)]
lib.generate_rsa_keypair.restype = None
lib.generate_ecdsa_keypair.argtypes = [ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_char_p)]
lib.generate_ecdsa_keypair.restype = None

logger = logging.getLogger(__name__)

# Intel DCAP QVL quote verification is not safe for concurrent calls in one process.
_dcap_quote_verify_lock = threading.Lock()

# CMD definitions 
REQ_CERT = "REQ_CERT"
VERIFY_CERT = "VERIFY_CERT"

class RPE:
    def __init__(self):
        self.conf = self.load_conf()
        conf = self.conf["rpe"]
        self.signing_keys = None
        self.encryption_keys = None
        self.grpc_server_address = conf["grpc_server_address"]
        self.rpo_address = conf["rpo_address"]
        self.rpo_port = conf["rpo_port"]
        self.rpe_port = conf["rpe_port"]
        self.local_rpe = {
            "rpe_id": conf["rpe_id"]
        }
        self.rpes = None
        self.session_id = None
        self.rpe_ids = None
        self.rpe_mr = None
        self.rpe_mrsigner = None
        self.rpe_isvprodid = None
        self.rpe_isvsvn = None
        self.policies_obj = None
        self.collaterals = None
        self.num_rpes_in_policies = None
        self.rpo_verification_result = None
        self.ratls = ratls.RATLS()
        self.ft_manager = None
        self.policies_json_text = None
        self.local_policy = None
        self.consensus_policy = None
        self.consensus_policy_hash = None
        self.peer_policy_hashes = {}
        self.ft_recovery_cache_available = False
        self.ft_phase2_evidence_quote = None
    
    def start(self):
        # =============== Performance test: record initialization start time ===============
        init_start_time = time.time()
        perf_timestamps = {
            "rpe_id": self.local_rpe["rpe_id"],
            "init_start": init_start_time,
            "phase1_start": None,
            "phase1_end": None,
            "phase2_start": None,
            "phase2_quote_generation_start": None,
            "phase2_quote_generation_end": None,
            "phase2_exchange_start": None,
            "phase2_send_local_quote_start": None,
            "phase2_send_local_quote_end": None,
            "phase2_wait_remote_quotes_start": None,
            "phase2_wait_remote_quotes_end": None,
            "phase2_exchange_end": None,
            "phase2_verification_start": None,
            "phase2_verification_end": None,
            "phase2_end": None,
            "init_complete": None
        }
        
        # Generate signing keys and encryption keys
        logger.info("Generating keys...")
        self.generate_keys()
        public_signing_key_pem = self.signing_keys["public"].public_bytes(encoding=serialization.Encoding.PEM, 
                                                                          format=serialization.PublicFormat.SubjectPublicKeyInfo)
        public_encryption_key_pem = self.encryption_keys["public"].public_bytes(encoding=serialization.Encoding.PEM,
                                                            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        logger.info("done.")
        
        # Pre-init ready: RPE has keys and client init; test script can start RPO now (for Phase2 test)
        perf_data_dir = "./performance_data"
        os.makedirs(perf_data_dir, exist_ok=True)
        pre_init_ready_file = os.path.join(perf_data_dir, "rpe_pre_init_ready_{}.flag".format(self.local_rpe["rpe_id"]))
        try:
            with open(pre_init_ready_file, "w") as f:
                f.write("{}\n".format(time.time()))
        except Exception as e:
            logger.warning("Could not write pre-init ready file %s: %s" % (pre_init_ready_file, e))

        self.ft_recovery_cache_available = self.has_ft_expt_cache()
        policies = None
        phase1_duration = 0.0
        skip_phase2_for_recovery = False

        # =============== Phase one ===============
        if self.ft_recovery_cache_available:
            logger.info("======================= Starting FT recovery startup... =======================")
            logger.error("====== SRAS-FT recovery startup: using cached Expt; skip RPO authorization and phase two =======")
            perf_timestamps["phase1_start"] = time.time()
            policies = self.load_ft_expt_cache()
            if policies is None:
                logger.error("SRAS-FT recovery startup failed: cannot load cached Expt")
                return
            self.policies_json_text = policies
            self.rpo_verification_result = "RECOVERY_CACHE"
            perf_timestamps["phase1_end"] = time.time()
            phase1_duration = perf_timestamps["phase1_end"] - perf_timestamps["phase1_start"]
            skip_phase2_for_recovery = True
        else:
            logger.info("======================= Starting phase one... =======================")
            logger.error("====== Performace test: phase one start =======")
            perf_timestamps["phase1_start"] = time.time()
            # Initialize RA-TLS client (init only, does not connect to RPO)
            success = self.ratls.client(self.rpo_address, self.rpo_port)
            if not success:
                return
            # Set public keys to RPO
            # if self.ratls.set_public_keys(public_signing_key_pem, public_encryption_key_pem) != 0:
            #     logger.error("Failed to pass public keys")
            #     return
            
            # Get policies from RPO
            policies, self.rpo_verification_result = self.ratls.get_policies()
            if policies is None:
                logger.error("Get policies from RPO failed")
                return
            self.policies_json_text = policies
            logger.info("RPE successfully attested by RPO, verification result: %s" % self.rpo_verification_result)

        # Parse policies
        policies_json = json.loads(policies)
        self.policies_obj = Policies(policies_json)
        self.local_policy = policies_json
        self.session_id = self.policies_obj.getSesssionId()
        self.rpe_mr = self.policies_obj.getRPEMR()
        self.rpe_mrsigner = self.policies_obj.getRPEMRSigner()
        self.rpe_isvprodid = self.policies_obj.getRPEISVProdID()
        self.rpe_isvsvn = self.policies_obj.getRPEISVSVN()
        self.num_rpes_in_policies = self.policies_obj.getNumberOfRPE()
        if not self.ft_recovery_cache_available:
            self.cache_ft_expt_if_enabled()
            
        # Load collateral
        logger.info("Loading collateral...")
        tcb_ids = self.policies_obj.getTcbIds()
        collateral_dict = dict()
        for tcb_id in tcb_ids:
            file_path = "collaterals/" + tcb_id + ".dat"
            collateral = self.load_collateral(file_path)
            collateral_dict[tcb_id] = collateral
        self.collaterals = collateral_dict
        logger.info("Done.")
        
        # Compute the hash of session id
        session_id_hash_bytes = None
        if self.session_id is not None:
            session_id_hash_bytes = self.compute_message_hash(bytes(self.session_id, "UTF-8"), SHA384)
        
        # Store the local rpe details
        self.local_rpe["details"] = {
            "session_id_hash": str(session_id_hash_bytes),
            "rpe_public_signing_key": public_signing_key_pem.decode(),
            "rpe_public_encryption_key": public_encryption_key_pem.decode(),
            "rpo_verification_result": self.rpo_verification_result
        }
        rpe_verification_info = {
            "rpe_id": self.local_rpe["rpe_id"],
            "details": self.local_rpe["details"]
        }
        
        # Build rpes from policies 
        logger.info("Building RPEs information from policies...")
        rpes = dict()
        # Get all RPE IDs from policies
        policies_data_json = self.policies_obj.policies_data_json
        all_rpe_ids = [rpe["id"] for rpe in policies_data_json["rpe"]]
        if len(all_rpe_ids) == 0:
            logger.error("Failed to get all RPE IDs from plocies")
            return
        
        logger.info("Pre-computing collateral hashes...")
        collateral_hashes = {}
        for tcb_id, collateral in self.collaterals.items():
            collateral_hash_compute = self.compute_message_hash(collateral.encode('UTF-8'), SHA384)
            collateral_base64_hash_compute = crypto_utility.byte_array_to_base64(collateral_hash_compute)
            collateral_hashes[tcb_id] = collateral_base64_hash_compute
            logger.info("------Collateral hash for tcb %s: %s", tcb_id, collateral_base64_hash_compute)
        
        logger.info("Verify hash of all TCBs' collateral from policies...")
        for rpe_id in all_rpe_ids:
            rpo_public_signing_key = self.policies_obj.getPublicSigningKey(rpe_id)
            qeids = self.policies_obj.getRPEQEID(rpe_id)
            rpe_tcb_ids, tcb_infos = self.policies_obj.getRPETCBInfo(rpe_id)
            for tcb_id in rpe_tcb_ids:
                collateral_base64_hash_from_policies = tcb_infos[tcb_id]
                if tcb_id in collateral_hashes:
                    if collateral_base64_hash_from_policies != collateral_hashes[tcb_id]:
                        logger.error("Collateral hash mismatch for rpe %s, tcb %s", rpe_id, tcb_id)
                        return
                else:
                    logger.error("Collateral %s not found", tcb_id)
                    return
            
            collateral_base64 = self.collaterals.get(rpe_tcb_ids[0])
            if collateral_base64 is None:
                logger.error("Collateral %s not found", rpe_tcb_ids[0])
                return
            # Build rpes details from policies
            rpes[rpe_id] = {
                "rpe_id": rpe_id,
                "rpo_public_signing_key": rpo_public_signing_key,
                "collateral": collateral_base64,
                "qeid": qeids,
                "details": {
                    "rpe_public_signing_key": None,
                    "rpe_public_encryption_key": None,
                    "rpo_verification_result": None
                }
            }
        self.rpes = rpes

        logger.info("Verify TCBs' collateral Succeed! ")
        if not skip_phase2_for_recovery:
            perf_timestamps["phase1_end"] = time.time()
            phase1_duration = perf_timestamps["phase1_end"] - perf_timestamps["phase1_start"]
            logger.error("Phase 1 duration: %.3f seconds" % phase1_duration)
            logger.info("======================= Phase one finished =======================\n")
        else:
            logger.error("FT recovery cached Expt load duration: %.3f seconds" % phase1_duration)
            logger.info("======================= FT recovery startup Expt load finished =======================\n")
	        
        # =============== Phase two ===============
        perf_timestamps["phase2_start"] = time.time()
        logger.info("======================= Starting phase two... =======================")
        phase2_native_quote_verification_duration = 0.0
        phase2_policy_enforcement_duration = 0.0
        if self.rpes is not None:
            self.rpe_ids = ",".join(self.rpes.keys())

        if skip_phase2_for_recovery:
            logger.info("SRAS-FT recovery startup skips phase two mutual attestation")
            perf_timestamps["init_complete"] = time.time()
            total_duration = perf_timestamps["init_complete"] - perf_timestamps["init_start"]
            logger.error("Phase 2 skipped for SRAS-FT recovery startup")
            logger.error("Total initialization duration: %.3f seconds" % total_duration)
            perf_data = {
                "rpe_id": perf_timestamps["rpe_id"],
                "timestamps": perf_timestamps,
                "durations": {
                    "phase1": phase1_duration,
                    "total": total_duration,
                    "ft_recovery_startup": True,
                    "phase2_skipped": True,
                    "phase2_skip_reason": "cached_expt_recovery",
                }
            }
            perf_file = f"./performance_data/rpe_perf_{self.local_rpe['rpe_id']}.json"
            with open(perf_file, 'w') as f:
                json.dump(perf_data, f, indent=2)
            logger.error("Performance data saved to %s" % perf_file)
        else:
	        
            local_policy_hash = None
            if self.local_policy is not None:
                local_policy_hash = consensus_policy.hash_policy(self.local_policy)
            elif policies is not None:
                local_policy_hash = bytes(
                    self.compute_message_hash(policies.encode('UTF-8'), SHA384)
                )

            # Generate quote (report_data = SHA384(PK_s ‖ H(ρ)) ‖ pad16)
            perf_timestamps["phase2_quote_generation_start"] = time.time()
            quote = None
            if local_policy_hash is not None:
                quote = self.generate_quote_with_policy_hash(
                    public_signing_key_pem.decode(),
                    local_policy_hash,
                )
            else:
                logger.error(" Get policies failed ! Can't generate quote !")
                return
        
            # Build Evidence Quote: quote + PK_s + policy_hash (no PK_e)
            if quote is not None:
                self.ft_phase2_evidence_quote = quote
                evidence_quote = {
                    "quote": quote,
                    "rpe_public_signing_key": public_signing_key_pem.decode(),
                    "policy_hash": local_policy_hash.hex(),
                }
                evidence_quote_json = json.dumps(evidence_quote)
                evidence_quote_base64 = crypto_utility.byte_array_to_base64(evidence_quote_json.encode('UTF-8'))
                perf_timestamps["phase2_quote_generation_end"] = time.time()
    
                logger.error("Sending Evidence Quote (quote + PK_s + policy_hash) to blockchain...")
                perf_timestamps["phase2_exchange_start"] = time.time()
                perf_timestamps["phase2_send_local_quote_start"] = perf_timestamps["phase2_exchange_start"]
                if not grpc_client.sendQuote(self.grpc_server_address, self.local_rpe["rpe_id"], evidence_quote_base64):
                    logger.error(" Send Evidence Quote to transport failed !")
                    return
                perf_timestamps["phase2_send_local_quote_end"] = time.time()
                perf_timestamps["phase2_wait_remote_quotes_start"] = perf_timestamps["phase2_send_local_quote_end"]
                logger.error("Done")
            else:
                logger.error(" Generate qoute failed !")
                return
            
            # Get all RPEs' Evidence Quote from transport service before verification.
            rpe_id_dict_to_be_fetched = set(self.rpes.keys())
            fetched_evidence_quotes = {}
            while True:
                rpe_ids = ",".join(rpe_id_dict_to_be_fetched)
                logger.error("Querying quotes for ids: %s", rpe_ids)
                query_started_at = time.time()
    
                status, evidence_quotes_base64 = grpc_client.queryQuoteByIds(self.grpc_server_address, rpe_ids)
                if not status:
                    logger.error("Failed to query quotes from blockchain")
                    return
                query_finished_at = time.time()
    
                evidence_quotes_dict = json.loads(evidence_quotes_base64)
                logger.error(
                    "QueryQuoteByIds finished in %.3fs, returned ids=%s",
                    query_finished_at - query_started_at,
                    sorted(evidence_quotes_dict.keys()),
                )
                if not evidence_quotes_dict:
                    time.sleep(0.05)
                    continue
                
                for rpe_id, evidence_quote_base64 in evidence_quotes_dict.items():
                    fetched_evidence_quotes[rpe_id] = evidence_quote_base64
                    rpe_id_dict_to_be_fetched.remove(rpe_id)
                    
                if len(rpe_id_dict_to_be_fetched) == 0:
                    break
                # P2P QueryQuoteByIds is non-blocking; poll until all peers arrive.
                time.sleep(0.05)
    
            perf_timestamps["phase2_wait_remote_quotes_end"] = time.time()
            perf_timestamps["phase2_exchange_end"] = time.time()
            perf_timestamps["phase2_verification_start"] = time.time()
    
            for rpe_id, evidence_quote_base64 in fetched_evidence_quotes.items():
                native_verify_start = time.time()
                rpe_info = self.rpes[rpe_id]
    
                # Parse Evidence Quote: quote + PK_s + policy_hash
                try:
                    evidence_quote_json = crypto_utility.base64_to_byte_array(evidence_quote_base64).decode('UTF-8')
                    evidence_quote = json.loads(evidence_quote_json)
                    base64_encoded_quote = evidence_quote["quote"]
                    rpe_public_signing_key = evidence_quote["rpe_public_signing_key"]
                    peer_policy_hash_hex = evidence_quote.get("policy_hash")
                    if not peer_policy_hash_hex:
                        logger.error("hash_mismatch: Evidence Quote for rpe %s missing policy_hash", rpe_id)
                        return
                    peer_policy_hash = bytes.fromhex(peer_policy_hash_hex)
                    # Optional legacy field retained if present
                    rpe_public_encryption_key = evidence_quote.get("rpe_public_encryption_key")
                except Exception as e:
                    logger.error(" Failed to parse Evidence Quote for rpe %s: %s", (rpe_id, str(e)))
                    return
                
                # Verify quote using DCAP
                quote_bytes = crypto_utility.base64_to_byte_array(base64_encoded_quote)
                collateral = rpe_info["collateral"]
                with _dcap_quote_verify_lock:
                    ret = verify_dcap_quote.teeVerifyQuote(base64_encoded_quote, len(quote_bytes), collateral)
                phase2_native_quote_verification_duration += time.time() - native_verify_start
                logger.info("quote verification for rpe %s result: %x" % (rpe_id, ret))
                if ret != 0 and ret != 0xa002 and ret != 0xa008:
                    logger.error("verification_failure: Quote verification failed for rpe %s", rpe_id)
                    return
    
                # Rebuild report_data from peer envelope (never local policy hash)
                policy_verify_start = time.time()
                report_data = consensus_policy.build_evidence_report_data(
                    rpe_public_signing_key, peer_policy_hash
                )
                base64_encoded_report_data = crypto_utility.byte_array_to_base64(report_data)
        
                rpe_policies_to_verify = {
                    "mr_enclave": self.rpe_mr,
                    "mr_signer": self.rpe_mrsigner,
                    "isv_prod_id": self.rpe_isvprodid,
                    "isv_svn": self.rpe_isvsvn,
                    "base64_encoded_report_data": base64_encoded_report_data,
                    "qeid": rpe_info["qeid"][0]
                }
                rpe_policies_to_verify_json = json.dumps(rpe_policies_to_verify)
                with _dcap_quote_verify_lock:
                    ret = verify_dcap_quote.sgxVerifyQuoteBody(base64_encoded_quote, rpe_policies_to_verify_json)
                phase2_policy_enforcement_duration += time.time() - policy_verify_start
                logger.info("quote body verification for rpe %s result: %x" % (rpe_id, ret))
                if ret != 0:
                    logger.error("verification_failure: Quote body verification failed for rpe %s", rpe_id)
                    return
    
                logger.info("Verification successful for rpe %s, updating public keys", rpe_id)
                rpe_info["details"]["rpe_public_signing_key"] = rpe_public_signing_key
                if rpe_public_encryption_key is not None:
                    rpe_info["details"]["rpe_public_encryption_key"] = rpe_public_encryption_key
                self.peer_policy_hashes[rpe_id] = peer_policy_hash
    
            perf_timestamps["phase2_verification_end"] = time.time()

            # Phase2b: exchange full policies and compute consensus π*
            try:
                self._exchange_policies_and_compute_consensus(perf_timestamps)
            except consensus_policy.JoinError as join_err:
                logger.error("negotiation_abort: %s", join_err)
                return
            except Exception as e:
                logger.error("negotiation_abort: policy exchange/join failed: %s", e)
                return
            
            logger.info("======================= Phase two finished =======================\n")
            perf_timestamps["phase2_end"] = time.time()
            perf_timestamps["init_complete"] = perf_timestamps["phase2_end"]
            phase2_quote_generation_duration = perf_timestamps["phase2_quote_generation_end"] - perf_timestamps["phase2_quote_generation_start"]
            phase2_send_local_quote_duration = perf_timestamps["phase2_send_local_quote_end"] - perf_timestamps["phase2_send_local_quote_start"]
            phase2_wait_remote_quotes_duration = perf_timestamps["phase2_wait_remote_quotes_end"] - perf_timestamps["phase2_wait_remote_quotes_start"]
            phase2_exchange_duration = perf_timestamps["phase2_exchange_end"] - perf_timestamps["phase2_exchange_start"]
            phase2_verification_duration = perf_timestamps["phase2_verification_end"] - perf_timestamps["phase2_verification_start"]
            phase2_duration = perf_timestamps["phase2_end"] - perf_timestamps["phase2_start"]
            total_duration = perf_timestamps["init_complete"] - perf_timestamps["init_start"]
            logger.error("Phase 2 duration: %.3f seconds" % phase2_duration)
            logger.error("Phase 2.1 local quote generation duration: %.3f seconds" % phase2_quote_generation_duration)
            logger.error("Phase 2.2 quote exchange duration: %.3f seconds" % phase2_exchange_duration)
            logger.error("Phase 2.2.1 send local quote duration: %.3f seconds" % phase2_send_local_quote_duration)
            logger.error("Phase 2.2.2 wait remote quotes duration: %.3f seconds" % phase2_wait_remote_quotes_duration)
            logger.error("Phase 2.3 quote verification duration: %.3f seconds" % phase2_verification_duration)
            logger.error("Phase 2.3.1 native quote verification duration: %.3f seconds" % phase2_native_quote_verification_duration)
            logger.error("Phase 2.3.2 policy enforcement duration: %.3f seconds" % phase2_policy_enforcement_duration)
            t_exchange = perf_timestamps.get("t_exchange")
            t_join = perf_timestamps.get("t_join")
            if t_exchange is not None:
                logger.error("Phase 2.4 policy exchange duration (t_exchange): %.6f seconds" % t_exchange)
            if t_join is not None:
                logger.error("Phase 2.5 consensus join duration (t_join): %.6f seconds" % t_join)
            logger.error("Total initialization duration: %.3f seconds" % total_duration)
    
            # =============== Performance test: save timestamps to file ===============
            perf_data = {
                "rpe_id": perf_timestamps["rpe_id"],
                "timestamps": perf_timestamps,
                "durations": {
                    "phase1": phase1_duration,
                    "phase2": phase2_duration,
                    "phase2_quote_generation": phase2_quote_generation_duration,
                    "phase2_exchange": phase2_exchange_duration,
                    "phase2_send_local_quote": phase2_send_local_quote_duration,
                    "phase2_wait_remote_quotes": phase2_wait_remote_quotes_duration,
                    "phase2_verification": phase2_verification_duration,
                    "phase2_native_quote_verification": phase2_native_quote_verification_duration,
                    "phase2_policy_enforcement": phase2_policy_enforcement_duration,
                    "t_exchange": t_exchange,
                    "t_join": t_join,
                    "total": total_duration
                }
            }
            perf_file = f"./performance_data/rpe_perf_{self.local_rpe['rpe_id']}.json"
            with open(perf_file, 'w') as f:
                json.dump(perf_data, f, indent=2)
            logger.error("Performance data saved to %s" % perf_file)

        # =============== Phase three ===============
        logger.info("======================= Starting phase three... =======================")
        logger.error("====== Performace test: phase three start =======")
        self.initialize_ft_if_enabled()
        if not self.perform_ft_recovery_if_cached():
            logger.error("SRAS-FT recovery startup failed; aborting before phase three serving")
            return
        # Performance test: initialize Phase 3 performance data.
        phase3_perf_data = {
            "rpe_id": self.local_rpe["rpe_id"],
            "ce_authentications": []
        }
        
        # get TCB collateral data according to the policies
        ce_tcb_ids = self.policies_obj.getCETcbIds(self.local_rpe["rpe_id"])
        ce_collateral_dict = dict()
        for ce_tcb_id in ce_tcb_ids:
            ce_collateral_dict[ce_tcb_id] = json.loads(self.collaterals[ce_tcb_id])
        ce_collaterals = json.dumps(ce_collateral_dict)
        # initialize TCB info for verifying CE
        self.ratls.init_tcb_info(ce_collaterals)
        
        # RPE starts server port.
        ret = self.ratls.server_init(self.rpe_port)
        if ret != 0:
            logger.error(f"RA-TLS server initialization failed on port {self.rpe_port}")
            return

        while True:
            if self.ratls.wait_for_connection() !=0:
                logger.error("CE connection failed")
                continue
            logger.info("CE connected")

            if self.ft_manager is not None and self.ft_manager.config.enabled:
                pending_result = self.ft_manager.process_pending_evidence_updates()
                if pending_result.get("processed", 0) > 0:
                    logger.info(
                        "SRAS-FT processed pending EvidenceUpdate before CE authentication: %s",
                        pending_result,
                    )

            # Performance test: record CE authentication start time.
            ce_auth_start = time.time()
            ce_id = None
            stage3_native_quote_verification_duration = None
            stage3_expectation_policy_enforcement_duration = None
            stage3_verification_duration = None
            ft_state_propagation_duration = None
            ft_state_propagation_timings = {}
            ft_echo_count = 0

            if self.ratls.perform_handshake() != 0:
                logger.error("RA-TLS handshake with CE failed")
                self.ratls.close_connection()
                continue

            if self.ratls.verify_peer() != 0:
                logger.error("CE attestation failed")
                self.ratls.close_connection()
                continue
            stage3_verify_peer_end = time.time()
            stage3_native_quote_verification_duration = stage3_verify_peer_end - ce_auth_start

            # receive commands from CE
            command = self.ratls.receive_commands()
            if command is None:
                logger.error("Receive command from CE failed")
                self.ratls.close_connection()
                continue

            if command == REQ_CERT:
                stage3_verify_ce_body_start = time.time()
                ret = self.ratls.get_ce_info()
                if ret != 0:
                    logger.error("Get CE info failed")
                    self.ratls.close_connection()
                    continue
                # verify ce quote body
                ce_id = self.ratls.get_ce_id()
                ces_info = self.policies_obj.getCEinfo(self.local_rpe["rpe_id"], ce_id)
                if ces_info is None:
                    logger.error("Cannot resolve ces info of ce %s", ce_id)
                    self.ratls.close_connection()
                    continue
                ret = self.ratls.verify_ce_body(ces_info)
                stage3_verify_ce_body_end = time.time()
                stage3_expectation_policy_enforcement_duration = (
                    stage3_verify_ce_body_end - stage3_verify_ce_body_start
                )
                if ret < 0:
                    logger.error("CE body verification failed")
                    self.ratls.close_connection()
                    continue
                # Get CE public keys
                CESigningkey = self.ratls.get_ce_cert_pubkey_pem()
                ce_public_signing_key_obj = serialization.load_pem_public_key(CESigningkey, backend=openssl_backend)

                if self.ft_manager is not None and self.ft_manager.config.enabled:
                    ft_state_propagation_start = time.time()
                    ft_ok, ft_echoes = self.ft_manager.propagate_attestation_state(ce_id)
                    ft_state_propagation_duration = time.time() - ft_state_propagation_start
                    ft_echo_count = len(ft_echoes)
                    ft_state_propagation_timings = getattr(
                        self.ft_manager, "last_propagation_timings", {}
                    )
                    if not ft_ok:
                        logger.error(
                            "SRAS-FT quorum not reached for CE %s; aborting certificate issuance",
                            ce_id,
                        )
                        self.ratls.close_connection()
                        continue
                    logger.info(
                        "SRAS-FT quorum reached for CE %s with %d echo(es) in %.3f seconds",
                        ce_id,
                        ft_echo_count,
                        ft_state_propagation_duration,
                    )
                
                # Sign CE's public signing key and generate a cert.
                consensus_hash_hex = (
                    self.consensus_policy_hash.hex()
                    if self.consensus_policy_hash is not None
                    else None
                )
                ce_cert = certificate.generate_ce_certificate(
                    self.signing_keys["private"],
                    ce_public_signing_key_obj,
                    self.local_rpe["rpe_id"],
                    consensus_policy_hash=consensus_hash_hex,
                )
                ce_cert_base64 = crypto_utility.byte_array_to_base64(ce_cert)
                
                # Send CE's Certificate signed by RPE to CE
                ret = self.ratls.send_ce_cert(ce_cert_base64)
                if ret != 0:
                    logger.error("Send CE's Certificate signed by RPE to CE failed")
                    self.ratls.close_connection()
                    continue

                # Performance test: record CE authentication completion time when REQ_CERT completes.
                ce_auth_end = time.time()
                ce_auth_duration = ce_auth_end - ce_auth_start
                logger.info("CE %s authentication completed in %.3f seconds" % (ce_id, ce_auth_duration))
                logger.info("CE %s stage3 native quote verification duration: %.3f seconds" % (
                    ce_id, stage3_native_quote_verification_duration))
                logger.info("CE %s stage3 expectation-policy enforcement duration: %.3f seconds" % (
                    ce_id, stage3_expectation_policy_enforcement_duration))
                if ft_state_propagation_duration is not None:
                    logger.info("CE %s SRAS-FT state propagation duration: %.3f seconds" % (
                        ce_id, ft_state_propagation_duration))
                    logger.info(
                        "CE %s SRAS-FT state propagation timings: %s",
                        ce_id,
                        ft_state_propagation_timings,
                    )
                
                # Save performance data.
                # Check whether the file exists before writing after each authentication.
                # If it does not exist, this is a new test after cleanup, so reset the data.
                perf_file = f"./performance_data/rpe_phase3_perf_{self.local_rpe['rpe_id']}.json"
                
                # Before appending, read the existing file to validate its state.
                # If the file is missing or unreadable, reset phase3_perf_data.
                # This avoids writing stale data into a newly created file after manual deletion.
                file_exists_and_valid = False
                try:
                    if os.path.exists(perf_file):
                        # Try reading the file to verify that it is valid.
                        with open(perf_file, 'r') as f:
                            existing_data = json.load(f)
                            # Verify the file format.
                            if isinstance(existing_data, dict) and "rpe_id" in existing_data and "ce_authentications" in existing_data:
                                file_exists_and_valid = True
                                # Use valid existing data to preserve continuity.
                                phase3_perf_data = existing_data
                                logger.debug("Loaded existing perf data from %s with %d authentications" % 
                                           (perf_file, len(phase3_perf_data.get("ce_authentications", []))))
                except (FileNotFoundError, IOError, OSError, json.JSONDecodeError) as e:
                    # Reset when the file is missing, unreadable, or malformed.
                    logger.debug("Perf file %s not accessible or invalid: %s, resetting phase3_perf_data" % (perf_file, e))
                    file_exists_and_valid = False
                
                # Reset data when the file is missing or invalid.
                if not file_exists_and_valid:
                    logger.info("Perf file %s not found or invalid, resetting phase3_perf_data (new test detected)" % perf_file)
                    phase3_perf_data = {
                        "rpe_id": self.local_rpe["rpe_id"],
                        "ce_authentications": []
                    }
                
                phase3_perf_data["ce_authentications"].append({
                    "ce_id": ce_id,
                    "auth_start": ce_auth_start,
                    "auth_end": ce_auth_end,
                    "auth_duration": ce_auth_duration,
                    "stage3_native_quote_verification_duration": stage3_native_quote_verification_duration,
                    "stage3_expectation_policy_enforcement_duration": stage3_expectation_policy_enforcement_duration,
                    "stage3_verification_duration": stage3_verification_duration,
                    "ft_state_propagation_duration": ft_state_propagation_duration,
                    "ft_state_propagation_timings": ft_state_propagation_timings,
                    "ft_echo_count": ft_echo_count
                })
                
                # Save to file after each authentication.
                
                # In an SGX enclave, direct writes may hit permission issues after external deletion.
                # Write a temporary file and then rename it for safer updates.
                try:
                    # Use a temporary file name.
                    temp_file = perf_file + ".tmp"
                    
                    # Write the temporary file first.
                    with open(temp_file, 'w') as f:
                        json.dump(phase3_perf_data, f, indent=2)
                    
                    # Remove the target file first when it exists to avoid rename failures.
                    # The file may have been deleted externally, so check existence first.
                    if os.path.exists(perf_file):
                        try:
                            os.remove(perf_file)
                        except (PermissionError, OSError) as e:
                            # The file may already have been deleted; ignore FileNotFoundError.
                            if isinstance(e, FileNotFoundError):
                                pass  # Nothing to do when the file does not exist.
                            else:
                                logger.warning("Failed to remove existing perf file %s: %s" % (perf_file, e))
                    
                    # Rename the temporary file to the target file.
                    os.rename(temp_file, perf_file)
                except (PermissionError, IOError, OSError) as e:
                    logger.error("Failed to write performance data to %s: %s" % (perf_file, e))
                    # Clean up the temporary file when it still exists.
                    temp_file = perf_file + ".tmp"
                    if os.path.exists(temp_file):
                        try:
                            os.remove(temp_file)
                        except:
                            pass
                    # Continue without interrupting the authentication flow.

            elif command == VERIFY_CERT:
                collaborativeCERT = self.ratls.get_collaborative_ce_cert()
                if collaborativeCERT is None:
                    logger.error("Get collaborative CE certificate failed")
                    self.ratls.close_connection()
                    continue
                cert = certificate.parse_ce_certificate(collaborativeCERT)
                collaborativeRPEid = certificate.get_ce_certificate_rpeid(cert)
                logger.info("Certificate signed by RPE: %s", collaborativeRPEid)
                logger.info("Available RPEs: %s", list(self.rpes.keys()) if self.rpes else "None")

                collaborativeRPEkey = self.get_collaborativeRPEkey(collaborativeRPEid)
                if collaborativeRPEkey is None:
                    logger.error("Failed to get collaborative RPE key for RPE: %s", collaborativeRPEid)
                    self.ratls.close_connection()
                    continue
                
                expected_hash = (
                    self.consensus_policy_hash.hex()
                    if self.consensus_policy_hash is not None
                    else None
                )
                verification_result = certificate.verify_ce_certificate(
                    cert, collaborativeRPEkey, expected_consensus_policy_hash=expected_hash
                )
                ret = self.ratls.send_verification_result(verification_result)
                if ret != 0:
                    logger.error("Send verification result to CE failed")
                    self.ratls.close_connection()
                    continue
            else:
                logger.error("Unknown command from CE: %s", command)
    
            self.ratls.close_connection()           

    def get_collaborativeRPEkey(self, collaborativeRPEid):
        if type(collaborativeRPEid) != str:
            collaborativeRPEid = collaborativeRPEid.decode()
        
        if collaborativeRPEid not in self.rpes:
            logger.error("RPE %s not found in self.rpes", collaborativeRPEid)
            return None

        rpe_info = self.rpes[collaborativeRPEid]
        if "details" not in rpe_info:
            logger.error("RPE %s has no 'details' field", collaborativeRPEid)
            return None

        collaborative_rpe_public_signing_key = rpe_info["details"].get("rpe_public_signing_key")
        if collaborative_rpe_public_signing_key is None:
            logger.error("RPE %s public signing key is None. Phase2 may not have completed successfully.", collaborativeRPEid)
            return None
              
        try:
            collaborative_rpe_public_signing_key_obj = serialization.load_pem_public_key(
                collaborative_rpe_public_signing_key.encode(), backend=openssl_backend)
            return collaborative_rpe_public_signing_key_obj
        except Exception as e:
            logger.error("Failed to load public key for RPE %s: %s", collaborativeRPEid, str(e))
            return None

    def build_ft_peer_public_keys(self):
        keys = {}
        local_public_signing_key_pem = self.signing_keys["public"].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        keys[self.local_rpe["rpe_id"]] = local_public_signing_key_pem
        if self.rpes:
            for rpe_id, rpe_info in self.rpes.items():
                key = rpe_info.get("details", {}).get("rpe_public_signing_key")
                if key:
                    keys[rpe_id] = key
        return keys

    def initialize_ft_if_enabled(self):
        self.ft_manager = ft_control.FTControlManager(
            ft_control.FTConfig.from_conf(
                self.conf,
                num_rpes=self.num_rpes_in_policies or 1,
                local_rpe_id=self.local_rpe["rpe_id"],
            ),
            self.signing_keys["private"],
            self.signing_keys["public"].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode(),
            self.build_ft_peer_public_keys(),
            quote_verifier=self,
            on_peer_key_update=self.update_ft_peer_public_keys,
        )
        if self.ft_manager.config.enabled:
            self.ft_manager.start()
            logger.info("SRAS-FT control service started at %s", self.ft_manager.bound_address())

    def get_ft_expt_cache_path(self):
        ft_conf = self.conf.get("ft", {}) if isinstance(self.conf, dict) else {}
        return str(ft_conf.get("expt_cache_path", "collaterals/expt_cache.json")).strip().strip('"')

    def is_ft_enabled_in_config(self):
        ft_conf = self.conf.get("ft", {}) if isinstance(self.conf, dict) else {}
        return str(ft_conf.get("enabled", "false")).strip().strip('"').lower() in (
            "1",
            "true",
            "yes",
            "on",
        )

    def has_ft_expt_cache(self):
        return self.is_ft_enabled_in_config() and os.path.exists(self.get_ft_expt_cache_path())

    def cache_ft_expt_if_enabled(self):
        if not self.is_ft_enabled_in_config() or self.policies_json_text is None:
            return
        try:
            cache_path = self.get_ft_expt_cache_path()
            cache_dir = os.path.dirname(cache_path)
            if cache_dir:
                os.makedirs(cache_dir, exist_ok=True)
            payload = {
                "expt": self.policies_json_text,
                "expt_hash": self.get_ft_expt_hash(),
            }
            tmp_path = "%s.tmp" % cache_path
            with open(tmp_path, "w", encoding="utf-8") as cache_file:
                json.dump(payload, cache_file, sort_keys=True, separators=(",", ":"))
            os.replace(tmp_path, cache_path)
            logger.info("SRAS-FT cached Expt at %s", cache_path)
        except Exception as e:
            logger.error("SRAS-FT failed to cache Expt: %s", str(e))

    def load_ft_expt_cache(self):
        try:
            with open(self.get_ft_expt_cache_path(), "r", encoding="utf-8") as cache_file:
                payload = json.load(cache_file)
            policies = payload.get("expt")
            expt_hash = payload.get("expt_hash")
            if not policies or not expt_hash:
                logger.error("SRAS-FT Expt cache is missing expt or expt_hash")
                return None
            computed_hash = crypto_utility.byte_array_to_base64(
                self.compute_message_hash(policies.encode("UTF-8"), SHA384)
            )
            if computed_hash != expt_hash:
                logger.error("SRAS-FT Expt cache hash mismatch")
                return None
            return policies
        except Exception as e:
            logger.error("SRAS-FT failed to load Expt cache: %s", str(e))
            return None

    def validate_ft_expt_cache(self):
        try:
            with open(self.get_ft_expt_cache_path(), "r", encoding="utf-8") as cache_file:
                payload = json.load(cache_file)
            return payload.get("expt_hash") == self.get_ft_expt_hash()
        except Exception as e:
            logger.error("SRAS-FT failed to validate Expt cache: %s", str(e))
            return False

    def perform_ft_recovery_if_cached(self):
        if self.ft_manager is None or not self.ft_manager.config.enabled:
            return True
        if not self.ft_recovery_cache_available:
            logger.info("SRAS-FT recovery skipped: no startup Expt cache")
            return True
        recovery_started = time.perf_counter()
        logger.info("SRAS-FT recovery stage: validate Expt cache")
        if not self.validate_ft_expt_cache():
            logger.error("SRAS-FT recovery aborted: cached Expt hash does not match current Expt")
            return False
        logger.info("SRAS-FT recovery stage: warmup FT peer channels begin")
        warmup_result = self.ft_manager.warmup_peer_channels(timeout=2.0, retry_timeout=2.0)
        logger.info(
            "SRAS-FT recovery stage: warmup FT peer channels end warmed=%d/%d elapsed=%.3fms",
            warmup_result.get("warmed", 0),
            warmup_result.get("total", 0),
            warmup_result.get("elapsed_ms", 0.0),
        )
        logger.info(
            "SRAS-FT recovery stage: RecoveryQuery begin (quorum=%d timeout=%.1fs)",
            self.ft_manager.config.ft_quorum,
            self.ft_manager.config.recovery_timeout_sec,
        )
        recover_started = time.perf_counter()
        ok, selected_state, responses = self.ft_manager.recover_latest_attestation_state()
        recover_elapsed_ms = ft_control.elapsed_ms(recover_started)
        logger.error(
            "====== SRAS-FT RecoveryQuery END ====== ok=%s responses=%d elapsed=%.3fs",
            ok,
            len(responses),
            recover_elapsed_ms / 1000.0,
        )
        if not ok:
            logger.error(
                "SRAS-FT recovery failed: valid recovery responses=%d quorum=%d",
                len(responses),
                self.ft_manager.config.ft_quorum,
            )
            return False
        logger.info(
            "SRAS-FT recovery restored state for tee %s with counter %s",
            selected_state["state"]["tee_id"],
            selected_state["state"]["attestation_counter"],
        )

        new_quote_started = time.perf_counter()
        logger.info("SRAS-FT recovery stage: generate new evidence quote begin")
        evidence = self.generate_evidence_quote(ft_control.random_nonce())
        new_quote_generation_ms = ft_control.elapsed_ms(new_quote_started)
        logger.info(
            "SRAS-FT recovery stage: generate new evidence quote end elapsed=%.3fms",
            new_quote_generation_ms,
        )
        logger.info("SRAS-FT recovery stage: EvidenceUpdate broadcast begin (dispatch only)")
        update_ok, peers = self.ft_manager.broadcast_evidence_update(evidence)
        logger.info(
            "SRAS-FT recovery stage: EvidenceUpdate broadcast dispatched ok=%s peers=%d",
            update_ok,
            len(peers),
        )
        self.cache_ft_expt_if_enabled()
        timings = dict(getattr(self.ft_manager, "last_recovery_timings", {}) or {})
        timings["new_quote_generation_ms"] = new_quote_generation_ms
        timings["total_recovery_ms"] = (
            timings.get("recovery_success_ms")
            or timings.get("total_recover_latest_ms")
            or ft_control.elapsed_ms(recovery_started)
        )
        timings["rpe_id"] = self.local_rpe["rpe_id"]
        timings["valid_response_count"] = len(responses)
        timings["quorum"] = self.ft_manager.config.ft_quorum
        timings["selected_tee_id"] = selected_state["state"]["tee_id"]
        timings["selected_attestation_counter"] = int(selected_state["state"]["attestation_counter"])
        timings["warmup_elapsed_ms"] = warmup_result.get("elapsed_ms", 0.0)
        timings["warmup_warmed_peers"] = warmup_result.get("warmed", 0)
        timings["warmup_total_peers"] = warmup_result.get("total", 0)
        self.write_ft_recovery_perf(timings)
        total_ms = timings.get("total_recovery_ms") or 0.0
        logger.error(
            "====== SRAS-FT RECOVERY TIMING SUMMARY ====== "
            "total_recovery_ms=%.3fs | recovery_success=%.3fs | "
            "full_query_collection=%.3fs | new_quote=%.3fs | broadcast=%.3fs | "
            "tee=%s counter=%s valid=%d/%d",
            total_ms / 1000.0,
            (timings.get("recovery_success_ms") or 0.0) / 1000.0,
            (timings.get("full_query_collection_ms") or 0.0) / 1000.0,
            (timings.get("new_quote_generation_ms") or 0.0) / 1000.0,
            (timings.get("new_quote_broadcast_ms") or 0.0) / 1000.0,
            timings.get("selected_tee_id"),
            timings.get("selected_attestation_counter"),
            timings.get("valid_response_count"),
            timings.get("quorum"),
        )
        return True

    def write_ft_recovery_perf(self, timings):
        perf_dir = "./performance_data"
        try:
            os.makedirs(perf_dir, exist_ok=True)
            perf_file = os.path.join(
                perf_dir, "rpe_ft_recovery_perf_%s.json" % self.local_rpe["rpe_id"]
            )
            with open(perf_file, "w", encoding="utf-8") as f:
                json.dump(timings, f, indent=2)
            logger.info("SRAS-FT recovery performance data saved to %s", perf_file)
        except Exception as e:
            logger.error("Failed to write SRAS-FT recovery performance data: %s", str(e))

    def get_public_signing_key_pem(self):
        return self.signing_keys["public"].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def get_public_encryption_key_pem(self):
        return self.encryption_keys["public"].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def get_ft_expt_hash(self):
        if self.policies_json_text is None:
            raise ValueError("policies are not loaded")
        expt_hash = self.compute_message_hash(self.policies_json_text.encode("UTF-8"), SHA384)
        return crypto_utility.byte_array_to_base64(expt_hash)

    def build_ft_quote_user_data(self, expt_hash, nonce):
        payload = {
            "expt_hash": expt_hash,
            "nonce": nonce,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def get_cached_phase2_evidence_for_recovery(self):
        if not self.ft_phase2_evidence_quote:
            raise RuntimeError("Phase 2 evidence quote is not available for recovery")
        return {
            "evidence_quote": self.ft_phase2_evidence_quote,
            "rpe_public_signing_key": self.get_public_signing_key_pem(),
            "rpe_public_encryption_key": self.get_public_encryption_key_pem(),
            "expt_hash": self.get_ft_expt_hash(),
        }

    def build_phase2_report_data(self, public_signing_key_pem, public_encryption_key_pem):
        if self.policies_json_text is None:
            raise ValueError("policies are not loaded")
        policies_hash_bytes = self.compute_message_hash(
            self.policies_json_text.encode("UTF-8"), SHA384
        )
        worker_data = public_signing_key_pem + public_encryption_key_pem
        keys_bytes = self.compute_message_hash(worker_data.encode("UTF-8"), SHA384)
        return bytes(keys_bytes) + bytes(policies_hash_bytes)

    def verify_phase2_evidence_quote(
        self,
        evidence_quote,
        public_signing_key_pem,
        public_encryption_key_pem,
        expt_hash,
        rpe_id=None,
    ):
        try:
            verify_total_started = time.perf_counter()
            if expt_hash != self.get_ft_expt_hash():
                logger.error("SRAS-FT Phase 2 evidence quote Expt hash mismatch for RPE %s", rpe_id)
                return False
            if rpe_id is None or self.rpes is None or rpe_id not in self.rpes:
                logger.error("SRAS-FT Phase 2 evidence quote verifier cannot resolve RPE %s", rpe_id)
                return False

            rpe_info = self.rpes[rpe_id]
            quote_bytes = crypto_utility.base64_to_byte_array(evidence_quote)
            logger.info("SRAS-FT Phase 2 teeVerifyQuote for rpe %s begin", rpe_id)
            with _dcap_quote_verify_lock:
                ret = verify_dcap_quote.teeVerifyQuote(
                    evidence_quote, len(quote_bytes), rpe_info["collateral"]
                )
            if ret != 0 and ret != 0xa002 and ret != 0xa008:
                return False

            report_data = self.build_phase2_report_data(
                public_signing_key_pem, public_encryption_key_pem
            )
            rpe_policies_to_verify = {
                "mr_enclave": self.rpe_mr,
                "mr_signer": self.rpe_mrsigner,
                "isv_prod_id": self.rpe_isvprodid,
                "isv_svn": self.rpe_isvsvn,
                "base64_encoded_report_data": crypto_utility.byte_array_to_base64(report_data),
                "qeid": rpe_info["qeid"][0],
            }
            logger.info("SRAS-FT Phase 2 sgxVerifyQuoteBody for rpe %s begin", rpe_id)
            with _dcap_quote_verify_lock:
                ret = verify_dcap_quote.sgxVerifyQuoteBody(
                    evidence_quote, json.dumps(rpe_policies_to_verify)
                )
            logger.info(
                "SRAS-FT Phase 2 evidence quote verification for rpe %s total %.3fms result=%x",
                rpe_id,
                (time.perf_counter() - verify_total_started) * 1000.0,
                ret,
            )
            return ret == 0
        except Exception as e:
            logger.error(
                "SRAS-FT Phase 2 evidence quote verification failed for RPE %s: %s",
                rpe_id,
                str(e),
            )
            return False

    def generate_evidence_quote(self, nonce):
        expt_hash = self.get_ft_expt_hash()
        signing_key = self.get_public_signing_key_pem()
        encryption_key = self.get_public_encryption_key_pem()
        quote_user_data = self.build_ft_quote_user_data(expt_hash, nonce)
        logger.info("SRAS-FT generate_evidence_quote: calling generate_quote_with_keys")
        quote_started = time.perf_counter()
        quote = self.generate_quote_with_keys(signing_key, encryption_key, quote_user_data)
        logger.info(
            "SRAS-FT generate_evidence_quote: generate_quote_with_keys done in %.3fms",
            (time.perf_counter() - quote_started) * 1000.0,
        )
        if quote is None:
            raise RuntimeError("failed to generate SRAS-FT evidence quote")
        return {
            "evidence_quote": quote,
            "rpe_public_signing_key": signing_key,
            "rpe_public_encryption_key": encryption_key,
            "expt_hash": expt_hash,
            "nonce": nonce,
        }

    def verify_evidence_quote(
        self,
        evidence_quote,
        public_signing_key_pem,
        public_encryption_key_pem,
        expt_hash,
        nonce,
        rpe_id=None,
    ):
        try:
            verify_total_started = time.perf_counter()
            hash_check_started = time.perf_counter()
            logger.info("SRAS-FT evidence quote Expt hash check for rpe %s begin", rpe_id)
            if expt_hash != self.get_ft_expt_hash():
                logger.error("SRAS-FT evidence quote Expt hash mismatch for RPE %s", rpe_id)
                return False
            logger.info(
                "SRAS-FT evidence quote Expt hash check for rpe %s done in %.3fms",
                rpe_id,
                (time.perf_counter() - hash_check_started) * 1000.0,
            )
            if rpe_id is None or self.rpes is None or rpe_id not in self.rpes:
                logger.error("SRAS-FT evidence quote verifier cannot resolve RPE %s", rpe_id)
                return False

            rpe_info = self.rpes[rpe_id]
            quote_bytes = crypto_utility.base64_to_byte_array(evidence_quote)
            native_verify_started = time.perf_counter()
            logger.info("SRAS-FT teeVerifyQuote for rpe %s begin", rpe_id)
            with _dcap_quote_verify_lock:
                ret = verify_dcap_quote.teeVerifyQuote(
                    evidence_quote, len(quote_bytes), rpe_info["collateral"]
                )
            logger.info(
                "SRAS-FT teeVerifyQuote for rpe %s done in %.3fms result=%x",
                rpe_id,
                (time.perf_counter() - native_verify_started) * 1000.0,
                ret,
            )
            if ret != 0 and ret != 0xa002 and ret != 0xa008:
                return False

            body_prepare_started = time.perf_counter()
            quote_user_data = self.build_ft_quote_user_data(expt_hash, nonce)
            report_data = self.generate_report_data(
                public_signing_key_pem, public_encryption_key_pem, quote_user_data
            )
            rpe_policies_to_verify = {
                "mr_enclave": self.rpe_mr,
                "mr_signer": self.rpe_mrsigner,
                "isv_prod_id": self.rpe_isvprodid,
                "isv_svn": self.rpe_isvsvn,
                "base64_encoded_report_data": crypto_utility.byte_array_to_base64(report_data),
                "qeid": rpe_info["qeid"][0],
            }
            logger.info(
                "SRAS-FT evidence quote body policy preparation for rpe %s done in %.3fms",
                rpe_id,
                (time.perf_counter() - body_prepare_started) * 1000.0,
            )
            body_verify_started = time.perf_counter()
            logger.info("SRAS-FT sgxVerifyQuoteBody for rpe %s begin", rpe_id)
            with _dcap_quote_verify_lock:
                ret = verify_dcap_quote.sgxVerifyQuoteBody(
                    evidence_quote, json.dumps(rpe_policies_to_verify)
                )
            logger.info(
                "SRAS-FT sgxVerifyQuoteBody for rpe %s done in %.3fms result=%x",
                rpe_id,
                (time.perf_counter() - body_verify_started) * 1000.0,
                ret,
            )
            logger.info(
                "SRAS-FT evidence quote verification for rpe %s total %.3fms",
                rpe_id,
                (time.perf_counter() - verify_total_started) * 1000.0,
            )
            return ret == 0
        except Exception as e:
            logger.error("SRAS-FT evidence quote verification failed for RPE %s: %s", rpe_id, str(e))
            return False

    def update_ft_peer_public_keys(self, rpe_id, public_signing_key_pem, public_encryption_key_pem):
        if self.rpes is None or rpe_id not in self.rpes:
            logger.error("SRAS-FT cannot update unknown recovering RPE %s", rpe_id)
            return False
        self.rpes[rpe_id]["details"]["rpe_public_signing_key"] = public_signing_key_pem
        self.rpes[rpe_id]["details"]["rpe_public_encryption_key"] = public_encryption_key_pem
        logger.info("SRAS-FT updated trusted public keys for recovering RPE %s", rpe_id)
        return True

    def generate_keys(self):
        private_signing_key = ec.generate_private_key(
                            curve=ec.SECP384R1(),
                            backend=openssl_backend)
        public_signing_key = private_signing_key.public_key()
        self.signing_keys = {
            "public": public_signing_key,
            "private": private_signing_key
        }
        
        private_encryption_key = rsa.generate_private_key(
                            public_exponent=65537,
                            key_size=3072,
                            backend=openssl_backend)
        public_encryption_key = private_encryption_key.public_key()
        self.encryption_keys = {
            "public": public_encryption_key,
            "private": private_encryption_key
        }
        
    def generate_keys_openssl(self):
        
        # Generate secp384r1 ECDSA key pair
        ecdsa_private_pem, ecdsa_public_pem = self.generate_ecdsa_keypair()
        # Generate RSA3072 key pair
        rsa_private_pem, rsa_public_pem = self.generate_rsa_keypair()
        
        # Import rsa and ecdsa key pair
        private_signing_key = SigningKey.from_pem(ecdsa_private_pem, hashfunc=hashlib.sha384)
        public_signing_key = VerifyingKey.from_pem(ecdsa_public_pem, hashfunc=hashlib.sha384)
        self.signing_keys = {
            "public": public_signing_key,
            "private": private_signing_key
        }
        
        private_encryption_key = RSA.import_key(rsa_private_pem)
        public_encryption_key = RSA.import_key(rsa_public_pem)
        self.encryption_keys = {
            "public": public_encryption_key,
            "private": private_encryption_key
        }
        
    def generate_rsa_keypair(self):
        private_pem = ctypes.c_char_p()
        public_pem = ctypes.c_char_p()
        lib.generate_rsa_keypair(ctypes.byref(private_pem), ctypes.byref(public_pem))
        private_pem_str = private_pem.value.decode()
        public_pem_str = public_pem.value.decode()
        lib.free(private_pem)
        lib.free(public_pem)
        return private_pem_str, public_pem_str

    def generate_ecdsa_keypair(self):
        private_pem = ctypes.c_char_p()
        public_pem = ctypes.c_char_p()
        lib.generate_ecdsa_keypair(ctypes.byref(private_pem), ctypes.byref(public_pem))
        private_pem_str = private_pem.value.decode()
        public_pem_str = public_pem.value.decode()
        lib.free(private_pem)
        lib.free(public_pem)
        return private_pem_str, public_pem_str
        
    def generate_quote_with_policy_hash(self, public_signing_key_pem, policy_hash):
        """Phase2 Evidence Quote: bind SHA384(PK_s ‖ H(ρ)) ‖ pad16 into report_data."""
        try:
            logger.info("Generating Quote with policy hash binding...")
            with _dcap_quote_verify_lock:
                fd = os.open("/dev/attestation/user_report_data", os.O_RDWR)
                report_data = consensus_policy.build_evidence_report_data(
                    public_signing_key_pem, bytes(policy_hash)
                )
                os.write(fd, report_data)
                os.close(fd)
                with open('/dev/attestation/quote', 'rb') as fd:
                    data = fd.read()
            logger.info("Quote generated")
            return crypto_utility.byte_array_to_base64(data)
        except Exception as e:
            logger.error("Generate quote with policy hash failed! Error message %s", str(e))
            return None

    def _exchange_policies_and_compute_consensus(self, perf_timestamps):
        """After mutual attestation: exchange ρ over quote channel and join to π*."""
        if self.local_policy is None:
            raise RuntimeError("local_policy is not loaded")

        local_rpe_id = self.local_rpe["rpe_id"]
        policy_json = json.dumps(self.local_policy, separators=(",", ":"), ensure_ascii=False)
        policy_b64 = crypto_utility.byte_array_to_base64(policy_json.encode("UTF-8"))

        perf_timestamps["phase2_policy_exchange_start"] = time.time()
        if not grpc_client.sendPolicy(self.grpc_server_address, local_rpe_id, policy_b64):
            raise RuntimeError("sendPolicy failed")

        rpe_ids = sorted(self.rpes.keys())
        fetched = {}
        pending = set(rpe_ids)
        while pending:
            status, content = grpc_client.queryPolicyByIds(
                self.grpc_server_address, ",".join(sorted(pending))
            )
            if not status:
                raise RuntimeError("queryPolicyByIds failed")
            blob = json.loads(content)
            for rid, b64 in blob.items():
                fetched[rid] = b64
                pending.discard(rid)
            if pending:
                time.sleep(0.05)
        perf_timestamps["phase2_policy_exchange_end"] = time.time()
        perf_timestamps["t_exchange"] = (
            perf_timestamps["phase2_policy_exchange_end"]
            - perf_timestamps["phase2_policy_exchange_start"]
        )

        policies_by_id = {}
        for rid, b64 in fetched.items():
            raw = crypto_utility.base64_to_byte_array(b64).decode("UTF-8")
            policy = json.loads(raw)
            digest = consensus_policy.hash_policy(policy)
            expected = self.peer_policy_hashes.get(rid)
            if rid == local_rpe_id:
                expected = consensus_policy.hash_policy(self.local_policy)
            if expected is None:
                raise RuntimeError("missing peer policy_hash for %s" % rid)
            if digest != expected:
                logger.error(
                    "hash_mismatch: received policy for %s does not match Evidence Quote policy_hash",
                    rid,
                )
                raise RuntimeError("policy hash mismatch for %s" % rid)
            policies_by_id[rid] = policy

        ordered = [policies_by_id[rid] for rid in sorted(policies_by_id.keys())]
        join_start = time.time()
        self.consensus_policy = consensus_policy.compute_consensus(ordered)
        self.consensus_policy_hash = consensus_policy.hash_policy(self.consensus_policy)
        join_end = time.time()
        perf_timestamps["phase2_join_start"] = join_start
        perf_timestamps["phase2_join_end"] = join_end
        perf_timestamps["t_join"] = join_end - join_start
        # Switch Attest lookups to π*
        self.policies_obj = Policies(self.consensus_policy)
        self._remap_collaterals_for_consensus()
        logger.info(
            "Consensus policy computed: H(π*)=%s t_exchange=%.6fs t_join=%.6fs",
            self.consensus_policy_hash.hex(),
            perf_timestamps["t_exchange"],
            perf_timestamps["t_join"],
        )

    def _remap_collaterals_for_consensus(self):
        """Map content-addressed TCB ids in π* to loaded collateral blobs."""
        if self.consensus_policy is None or self.collaterals is None:
            return
        hash_to_collateral = {}
        for tcb_id, collateral in self.collaterals.items():
            try:
                digest = self.compute_message_hash(collateral.encode("UTF-8"), SHA384)
                b64_hash = crypto_utility.byte_array_to_base64(bytes(digest))
                hash_to_collateral[b64_hash] = collateral
            except Exception:
                pass
            hash_to_collateral[tcb_id] = collateral
        remapped = dict(self.collaterals)
        for entry in self.consensus_policy.get("tcb") or []:
            eid = entry.get("id")
            data = entry.get("data")
            if eid in remapped:
                continue
            if data in hash_to_collateral:
                remapped[eid] = hash_to_collateral[data]
            else:
                logger.warning(
                    "No collateral remap for consensus tcb id %s (data=%s)",
                    eid,
                    data,
                )
        self.collaterals = remapped

    def generate_quote(self, user_data):
        try:
            logger.info("Generating Quote...")
            public_signing_key_pem = self.signing_keys["public"].public_bytes(encoding=serialization.Encoding.PEM, 
                                                                          format=serialization.PublicFormat.SubjectPublicKeyInfo)
            public_encryption_key_pem = self.encryption_keys["public"].public_bytes(encoding=serialization.Encoding.PEM,
                                                            format=serialization.PublicFormat.SubjectPublicKeyInfo)
            return self.generate_quote_with_keys(
                public_signing_key_pem.decode(),
                public_encryption_key_pem.decode(),
                user_data,
            )
        except Exception as e:
            logger.error(
                "Generate quote failed!"
                " Error message %(%s)" % str(e) )

    def generate_quote_with_keys(self, public_signing_key_pem, public_encryption_key_pem, user_data):
        try:
            logger.info("Generating Quote...")
            with _dcap_quote_verify_lock:
                fd = os.open("/dev/attestation/user_report_data", os.O_RDWR)
                report_data = self.generate_report_data(
                    public_signing_key_pem,
                    public_encryption_key_pem,
                    user_data)
                os.write(fd, report_data)
                os.close(fd)
                with open('/dev/attestation/quote', 'rb') as fd:
                    data = fd.read()
            logger.info("Quote generated")
            quote = crypto_utility.byte_array_to_base64(data)
            return quote
        except Exception as e:
            logger.error(
                "Generate quote failed!"
                " Error message %(%s)" % str(e) )
    
    def generate_report_data(self, vkey_pem, ekey_pem, user_data):
        try:
            worker_data = vkey_pem + ekey_pem
            keys_bytes = self.compute_message_hash(
                    worker_data.encode('UTF-8'), SHA384)
            user_data_bytes = self.compute_message_hash(
                    user_data.encode('UTF-8'), SHA384)
            return bytes(keys_bytes) + bytes(user_data_bytes)
        except Exception as e:
            logger.error(
                "Generate report data failed!"
                " Error message %(%s)" % str(e) )

    def load_conf(self):
        try:
            conf = pconfig.parse_configuration_files(
                    ["config.toml"],
                    ["/"])
            return conf
        except pconfig.ConfigurationException as e:
            logger.error(str(e))
            sys.exit(-1)
            
    def load_collateral(self, filepath):
        try:
            with open(filepath, "r") as fd:
                data = fd.read()
                fd.close()
            return data
        except Exception as e:
            logger.error(
                "Load collateral from %s failed!"
                " Error message %(%s)" % (filepath, str(e)) )
            return None
            
    def compute_message_hash(self, message_bytes, shafunc):
        """
        Computes message hash.

        Parameters :
            message_bytes: Message in bytes
        Returns :
            SHA* message hash.
        """
        hash_obj = shafunc.new()
        hash_obj.update(message_bytes)
        return hash_obj.digest()

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    logging.getLogger().setLevel(logging.INFO)
    logging.getLogger('__main__').setLevel(logging.INFO)
    logging.getLogger('rpe').setLevel(logging.INFO)
    logging.getLogger('certificate').setLevel(logging.INFO)
    logging.getLogger('ratls').setLevel(logging.INFO)
    logging.getLogger('policies').setLevel(logging.INFO)
    for name in logging.Logger.manager.loggerDict:
        logging.getLogger(name).setLevel(logging.INFO)
        
    rpe = RPE()
    rpe.start()
