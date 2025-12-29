import logging
import json
import sys
from crypto_utils import crypto_utility
from utility import config as pconfig
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends.openssl import backend as openssl_backend
import ratls
import policies

# CMD definitions 
CMD_GET_RPE_KEYS = "CMD_GET_KEYS"
CMD_SEND_MESSAGE = "CMD_SEND_MESSAGE"
CMD_RECV_MESSAGE = "CMD_RECV_MESSAGE"
CMD_EXIT         = "CMD_EXIT"
CMD_SEND_POLICY  = "CMD_SEND_POLICY"
RESP_OK          = "RESP_OK"
RESP_ERROR       = "RESP_ERROR"
RESP_BYE         = "RESP_BYE"

logger = logging.getLogger(__name__)

class RPO:
    def __init__(self):
        self.conf = self.load_conf()
        conf = self.conf["rpo"]
        self.policies_path = conf["policies_path"]
        self.private_key_path = conf["private_key_path"]
        self.evidence_path = conf["evidence_path"]
        self.policies = policies.Policies()
        self.ratls = ratls.RATLS()

        self.signing_keys = dict()

        self.port = conf["port"]
        self.managed_rpe = conf["rpe_id"]

        self.rpe_mr = None
        self.rpe_mrsigner = None
        self.rpe_isvprodid = None
        self.rpe_isvsvn = None
        self.rpe_qeid = None
        self.tcb_info = None
        self.collaterals = None

        self.policies_data = None
    
    def start(self):
        # =============== RPO initialization ===============
        logger.info("RPO initialization...")
        # Load private signing key
        self.load_private_signing_key()

        # Parsing Policies.
        self.policies_data = self.policies.load(self.policies_path)
        self.rpe_mr = self.policies.getRPEMR()
        self.rpe_mrsigner = self.policies.getRPEMRSigner()
        self.rpe_isvprodid = self.policies.getRPEISVProdID()
        self.rpe_isvsvn = self.policies.getRPEISVSVN()
        self.rpe_qeid = self.policies.getRPEQEID(self.managed_rpe)
        self.tcb_info = self.policies.getTCBInfo(self.managed_rpe)
        public_signing_key = self.policies.getPublicSigningKey(self.managed_rpe)
        logger.info("Loading rpe collateral...")
        tcb_ids = self.policies.getRpeTcbIds(self.managed_rpe)
        collateral_dict = dict()
        for tcb_id in tcb_ids:
            file_path = "collaterals/" + tcb_id + ".dat"
            collateral = self.load_collateral(file_path)
            collateral_dict[tcb_id] = collateral
        self.collaterals = collateral_dict
        logger.info("Done.")
        logger.info("public_signing_key:\n %s" % public_signing_key)
        self.signing_keys["public_signing_key"] = serialization.load_pem_public_key(public_signing_key.encode(), backend=openssl_backend)

        # =============== Phase one ===============
        logger.info("======================= Starting phase one... =======================")

        # Prepare verfication info that RPO verifies RPE including QEID and tcb info
        self.ratls.init_measurements(self.rpe_mr, self.rpe_mrsigner, self.rpe_isvprodid, self.rpe_isvsvn)
        self.ratls.init_qeid(self.rpe_qeid)
        self.ratls.init_tcb_info(self.collaterals[tcb_ids[0]])

        # RPO starts server port.
        ret = self.ratls.server_init(self.port)
        if ret == -1:
            logger.error(f"RA-TLS server initialization failed on port {self.port}")
            return

        while True:
            if self.ratls.wait_for_connection() != 0:
                logger.info("Waiting for RPE connection failed")
                continue
            logger.info("RPE connected")

            if self.ratls.perform_handshake() != 0:
                logger.info("RA-TLS handshake with RPE failed")
                self.ratls.close_connection()
                continue
            logger.info("RA-TLS handshake with RPE succeeded")

            if self.ratls.verify_peer() != 0:
                logger.info("RPE attestation failed")
                self.ratls.close_connection()
                continue

            # receive commands from RPE
            rpo_verification_result = None
            command =self.ratls.receive_commands()
            if command is None:
                logger.error("Receive command from RPE failed")
                self.ratls.close_connection()
                continue
            
            if command == CMD_GET_RPE_KEYS:
                # Get RPE's keys
                RPESigningkey, RPEEncryptionkey = self.ratls.get_rpe_public_keys()
                if RPESigningkey is None or RPEEncryptionkey is None:
                    logger.error("Get RPE public keys failed")
                    self.ratls.close_connection()
                    continue
                
                # Sign rpe's key.
                rpe_keys = {
                    "public_signing_key": RPESigningkey.decode(),
                    "public_encryption_key": RPEEncryptionkey.decode()
                }
                signature_bytes = self.signing_keys['private_signing_key'].sign(
                                            bytes(json.dumps(rpe_keys), "UTF-8"), ec.ECDSA(hashes.SHA384()))
                signature = crypto_utility.byte_array_to_base64(signature_bytes)
                rpo_verification_result_json = {
                    "rpe_keys": rpe_keys,
                    "sig": signature
                }
                rpo_verification_result = json.dumps(rpo_verification_result_json)
                logger.info("RPE public keys sent to RPO")
            elif command == CMD_SEND_POLICY:
                logger.info("RPO received policies request from RPE")
                # RPO attests RPE successfully, send policies to RPE
                rpo_verification_result = RESP_OK
                # Pass policy data, which will pass to RPE if the RPE verification is successful 
                ret = self.ratls.pass_policy_data(self.policies_data, rpo_verification_result)
                if ret != 0:
                    logger.error("Pass policy data to RPE failed")
                    self.ratls.close_connection()
                    continue
                logger.info("Policies sent to RPE")
            else:
                logger.error(f"Unknown command from RPE: {command}")
                self.ratls.close_connection()
                # ce_verification_result = self.ratls.getSomethingBuf() 
                # logger.info("======================= Phase three verification has finished =======================")
                # logger.info("CE verifcation result: %s" % ce_verification_result)
                        
                # # Get CE's keys from RPE once phase three is done
                # verification_result = {
                #     "rpo_verification_result": rpo_verification_result,
                #     "rpe_verification_result": rpe_verification_result,
                #     "ce_verification_result": ce_verification_result
                # }
                # verification_result_bytes = bytes(json.dumps(verification_result), "UTF-8")
                
                # # Write evidences to file
                # try:
                #     with open(self.evidence_path, 'wb') as fd:
                #         fd.write(verification_result_bytes)
                # except Exception as e:
                #     logger.error(
                #         "Write evidence failed!"
                #         " Error message %(%s)" % str(e) )
                
        self.ratls.server_cleanup()    


    def load_private_signing_key(self):
        logger.info("Read private signing key")
        try:
            with open(self.private_key_path, 'rb') as fd:
                data = fd.read()
            self.signing_keys["private_signing_key"] = serialization.load_pem_private_key(data, password=None, backend=openssl_backend)
        except Exception as e:
            logger.error(
                "Read private key failed!"
                " Error message %(%s)" % str(e) )
    
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
    
    def load_conf(self):
        try:
            conf = pconfig.parse_configuration_files(
                    ["config.toml"],
                    ["./"])
            return conf
        except pconfig.ConfigurationException as e:
            logger.error(str(e))
            sys.exit(-1)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    rpo = RPO()
    rpo.start()