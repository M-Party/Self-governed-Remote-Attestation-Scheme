import logging
import json
import ctypes
import os
import sys
import time
import hashlib
import grpc_client
from Cryptodome.Hash import SHA384
from ecdsa import SigningKey, VerifyingKey, NIST384p
from Cryptodome.PublicKey import RSA
from crypto_utils import crypto_utility
from quote_verification import verify_dcap_quote
import ratls
import certificate
from policies import Policies
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
    
    def start(self):
        # =============== 性能测试：记录初始化开始时间 ===============
        init_start_time = time.time()
        perf_timestamps = {
            "rpe_id": self.local_rpe["rpe_id"],
            "init_start": init_start_time,
            "phase1_start": None,
            "phase1_end": None,
            "phase2_start": None,
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
        
        # =============== Phase one ===============
        perf_timestamps["phase1_start"] = time.time()
        logger.info("======================= Starting phase one... =======================")
        # Initialize RA-TLS client 
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
        logger.info("RPE successfully attested by RPO, verification result: %s" % self.rpo_verification_result)

        # Parse policies
        policies_json = json.loads(policies)
        self.policies_obj = Policies(policies_json)
        self.session_id = self.policies_obj.getSesssionId()
        self.rpe_mr = self.policies_obj.getRPEMR()
        self.rpe_mrsigner = self.policies_obj.getRPEMRSigner()
        self.rpe_isvprodid = self.policies_obj.getRPEISVProdID()
        self.rpe_isvsvn = self.policies_obj.getRPEISVSVN()
        self.num_rpes_in_policies = self.policies_obj.getNumberOfRPE()
            
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
        perf_timestamps["phase1_end"] = time.time()
        phase1_duration = perf_timestamps["phase1_end"] - perf_timestamps["phase1_start"]
        logger.info("Phase 1 duration: %.3f seconds" % phase1_duration)
        logger.info("======================= Phase one finished =======================\n")
        
        # =============== Phase two ===============
        perf_timestamps["phase2_start"] = time.time()
        logger.info("======================= Starting phase two... =======================")
        if self.rpes is not None:
            self.rpe_ids = ",".join(self.rpes.keys())
        
        policies_hash = None
        if policies is not None:
            policies_hash_bytes = self.compute_message_hash(policies.encode('UTF-8'), SHA384)
            policies_hash = bytes(policies_hash_bytes)

        # Generate quote
        quote = None
        if policies is not None:
            quote = self.generate_quote(policies)
        else:
            logger.error(" Get policies failed ! Can't generate quote !")
            return
        
        # Build Evidence Quote: combine quote with public keys
        if quote is not None:
            # Create Evidence Quote JSON
            evidence_quote = {
                "quote": quote,
                "rpe_public_signing_key": public_signing_key_pem.decode(),
                "rpe_public_encryption_key": public_encryption_key_pem.decode()
            }
            evidence_quote_json = json.dumps(evidence_quote)
            # Base64 encode the Evidence Quote JSON for transmission
            evidence_quote_base64 = crypto_utility.byte_array_to_base64(evidence_quote_json.encode('UTF-8'))

            logger.info("Sending Evidence Quote (quote + public keys) to blockchain...")
            if not grpc_client.sendQuote(self.grpc_server_address, self.local_rpe["rpe_id"], evidence_quote_base64):
                logger.error(" Send Evidence Quote to fabric failed !")
                return
            logger.info("Done")
        else:
            logger.error(" Generate qoute failed !")
            return
        
        # Get the other rpes' Evidence Quote from fabric-service and do RA for them
        rpe_id_dict_to_be_verified = set(self.rpes.keys())
        while True:
            rpe_ids = ",".join(rpe_id_dict_to_be_verified)

            status, evidence_quotes_base64 = grpc_client.queryQuoteByIds(self.grpc_server_address, rpe_ids)
            if not status:
                logger.error("Failed to query quotes from blockchain")
                return

            evidence_quotes_dict = json.loads(evidence_quotes_base64)
            if not evidence_quotes_dict:
                continue
            
            for rpe_id, evidence_quote_base64 in evidence_quotes_dict.items():
                rpe_id_dict_to_be_verified.remove(rpe_id)
                rpe_info = self.rpes[rpe_id]

                # Parse Evidence Quote: decode and extract quote and public keys
                try:
                    evidence_quote_json = crypto_utility.base64_to_byte_array(evidence_quote_base64).decode('UTF-8')
                    evidence_quote = json.loads(evidence_quote_json)
                    base64_encoded_quote = evidence_quote["quote"]
                    rpe_public_signing_key = evidence_quote["rpe_public_signing_key"]
                    rpe_public_encryption_key = evidence_quote["rpe_public_encryption_key"]
                except Exception as e:
                    logger.error(" Failed to parse Evidence Quote for rpe %s: %s", (rpe_id, str(e)))
                    return
                
                # Verify quote using DCAP
                quote_bytes = crypto_utility.base64_to_byte_array(base64_encoded_quote)
                collateral = rpe_info["collateral"]
                ret = verify_dcap_quote.teeVerifyQuote(base64_encoded_quote, len(quote_bytes), collateral)
                logger.info("quote verification for rpe %s result: %x" % (rpe_id, ret))
                if ret != 0 and ret != 0xa002 and ret != 0xa008:
                    logger.error("Quote verification failed for rpe %s", rpe_id)
                    return

                # Generate report_data using public keys from Evidence Quote and local policies
                worker_data = rpe_public_signing_key + rpe_public_encryption_key
                keys_bytes = self.compute_message_hash(worker_data.encode('UTF-8'), SHA384)
                report_data = bytes(keys_bytes) + policies_hash
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
                ret = verify_dcap_quote.sgxVerifyQuoteBody(base64_encoded_quote, rpe_policies_to_verify_json)
                logger.info("quote body verification for rpe %s result: %x" % (rpe_id, ret))
                if ret != 0:
                    logger.error("Quote body verification failed for rpe %s", rpe_id)
                    return

                # Verification successful, update public keys in self.rpes
                logger.info("Verification successful for rpe %s, updating public keys", rpe_id)
                rpe_info["details"]["rpe_public_signing_key"] = rpe_public_signing_key
                rpe_info["details"]["rpe_public_encryption_key"] = rpe_public_encryption_key
                
            if len(rpe_id_dict_to_be_verified) == 0:
                break

            ####################################################################
            # if len(rpe_id_dict_to_be_verified) == 0 or \
            #    self.local_rpe["rpe_id"] not in rpe_id_dict_to_be_verified:
            #     break
            ####################################################################
        
        logger.info("======================= Phase two finished =======================\n")
        perf_timestamps["phase2_end"] = time.time()
        perf_timestamps["init_complete"] = perf_timestamps["phase2_end"]
        phase2_duration = perf_timestamps["phase2_end"] - perf_timestamps["phase2_start"]
        total_duration = perf_timestamps["init_complete"] - perf_timestamps["init_start"]
        logger.info("Phase 2 duration: %.3f seconds" % phase2_duration)
        logger.info("Total initialization duration: %.3f seconds" % total_duration)

        # =============== 性能测试：保存时间戳到文件 ===============
        perf_data = {
            "rpe_id": perf_timestamps["rpe_id"],
            "timestamps": perf_timestamps,
            "durations": {
                "phase1": phase1_duration,
                "phase2": phase2_duration,
                "total": total_duration
            }
        }
        perf_file = f"./performance_data/rpe_perf_{self.local_rpe['rpe_id']}.json"
        with open(perf_file, 'w') as f:
            json.dump(perf_data, f, indent=2)
        logger.error("Performance data saved to %s" % perf_file)

        # =============== Phase three ===============
        logger.info("======================= Starting phase three... =======================")

        # 性能测试：初始化 Phase 3 性能数据
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

            # 性能测试：记录 CE 认证开始时间
            ce_auth_start = time.time()
            ce_id = None

            if self.ratls.perform_handshake() != 0:
                logger.error("RA-TLS handshake with CE failed")
                self.ratls.close_connection()
                continue

            if self.ratls.verify_peer() != 0:
                logger.error("CE attestation failed")
                self.ratls.close_connection()
                continue

            # receive commands from CE
            command = self.ratls.receive_commands()
            if command is None:
                logger.error("Receive command from CE failed")
                self.ratls.close_connection()
                continue

            if command == REQ_CERT:
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
                if ret < 0:
                    logger.error("CE body verification failed")
                    self.ratls.close_connection()
                    continue
                # Get CE public keys
                CESigningkey = self.ratls.get_ce_cert_pubkey_pem()
                ce_public_signing_key_obj = serialization.load_pem_public_key(CESigningkey, backend=openssl_backend)
                
                # Sign CE's public signing key and generate a cert.
                ce_cert = certificate.generate_ce_certificate(self.signing_keys["private"], ce_public_signing_key_obj, self.local_rpe["rpe_id"])
                ce_cert_base64 = crypto_utility.byte_array_to_base64(ce_cert)
                
                # Send CE's Certificate signed by RPE to CE
                ret = self.ratls.send_ce_cert(ce_cert_base64)
                if ret != 0:
                    logger.error("Send CE's Certificate signed by RPE to CE failed")
                    self.ratls.close_connection()
                    continue

                # 性能测试：记录 CE 认证完成时间（REQ_CERT 完成）
                ce_auth_end = time.time()
                ce_auth_duration = ce_auth_end - ce_auth_start
                logger.info("CE %s authentication completed in %.3f seconds" % (ce_id, ce_auth_duration))
                
                # 保存性能数据
                # 在每次认证完成后，写入文件前检查文件是否存在
                # 如果文件不存在（说明是新测试，文件被清理了），重置数据
                perf_file = f"./performance_data/rpe_phase3_perf_{self.local_rpe['rpe_id']}.json"
                
                # 关键：在追加数据前，尝试读取现有文件来验证文件状态
                # 如果文件不存在或读取失败，则重置 phase3_perf_data
                # 这样可以确保在文件被手动删除后，不会将旧数据写入新文件
                file_exists_and_valid = False
                try:
                    if os.path.exists(perf_file):
                        # 尝试读取文件，验证文件是否有效
                        with open(perf_file, 'r') as f:
                            existing_data = json.load(f)
                            # 验证文件格式是否正确
                            if isinstance(existing_data, dict) and "rpe_id" in existing_data and "ce_authentications" in existing_data:
                                file_exists_and_valid = True
                                # 如果文件有效，使用现有数据（保持连续性）
                                phase3_perf_data = existing_data
                                logger.debug("Loaded existing perf data from %s with %d authentications" % 
                                           (perf_file, len(phase3_perf_data.get("ce_authentications", []))))
                except (FileNotFoundError, IOError, OSError, json.JSONDecodeError) as e:
                    # 文件不存在、读取失败或格式错误，需要重置
                    logger.debug("Perf file %s not accessible or invalid: %s, resetting phase3_perf_data" % (perf_file, e))
                    file_exists_and_valid = False
                
                # 如果文件不存在或无效，重置数据
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
                    "auth_duration": ce_auth_duration
                })
                
                # 保存到文件（每次认证后更新）
                
                # 在 SGX enclave 中，如果文件被外部删除，直接写入可能遇到权限问题
                # 使用临时文件然后重命名的方式，更安全可靠
                try:
                    # 使用临时文件名
                    temp_file = perf_file + ".tmp"
                    
                    # 先写入临时文件
                    with open(temp_file, 'w') as f:
                        json.dump(phase3_perf_data, f, indent=2)
                    
                    # 如果目标文件存在，先删除（避免重命名失败）
                    # 注意：文件可能已经被外部删除，所以先检查是否存在
                    if os.path.exists(perf_file):
                        try:
                            os.remove(perf_file)
                        except (PermissionError, OSError) as e:
                            # 文件可能已经被删除，忽略 FileNotFoundError
                            if isinstance(e, FileNotFoundError):
                                pass  # 文件不存在，无需处理
                            else:
                                logger.warning("Failed to remove existing perf file %s: %s" % (perf_file, e))
                    
                    # 重命名临时文件为目标文件
                    os.rename(temp_file, perf_file)
                except (PermissionError, IOError, OSError) as e:
                    logger.error("Failed to write performance data to %s: %s" % (perf_file, e))
                    # 清理临时文件（如果存在）
                    temp_file = perf_file + ".tmp"
                    if os.path.exists(temp_file):
                        try:
                            os.remove(temp_file)
                        except:
                            pass
                    # 继续执行，不中断认证流程

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
                
                verification_result = certificate.verify_ce_certificate(cert,collaborativeRPEkey)
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
        
    def generate_quote(self, user_data):
        try:
            logger.info("Generating Quote...")
            public_signing_key_pem = self.signing_keys["public"].public_bytes(encoding=serialization.Encoding.PEM, 
                                                                          format=serialization.PublicFormat.SubjectPublicKeyInfo)
            public_encryption_key_pem = self.encryption_keys["public"].public_bytes(encoding=serialization.Encoding.PEM,
                                                            format=serialization.PublicFormat.SubjectPublicKeyInfo)
            fd = os.open("/dev/attestation/user_report_data", os.O_RDWR)
            report_data = self.generate_report_data(
                public_signing_key_pem.decode(),
                public_encryption_key_pem.decode(),
                user_data)
            os.write(fd, report_data)
            os.close(fd)
            # logger.info("report data hex = {}".format(report_data.hex()))
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
    logging.getLogger('certificate').setLevel(logging.ERROR)
    logging.getLogger('ratls').setLevel(logging.ERROR)
    logging.getLogger('policies').setLevel(logging.ERROR)
    for name in logging.Logger.manager.loggerDict:
        logging.getLogger(name).setLevel(logging.INFO)
        
    rpe = RPE()
    rpe.start()
